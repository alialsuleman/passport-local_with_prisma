const express = require('express');
const session = require('express-session');
var passport = require('passport');
var crypto = require('crypto');
const { serialize, deserialize } = require('v8');
var LocalStrategy = require('passport-local').Strategy;
const prisma = require('./services/prisma.ts')
const path = require('path');



/**
 * -------------- GENERAL SETUP ----------------
 */




async function add() {
    const user = await prisma.user.create({
        data:
        {

            username: "Asdasdasd",
            hash: "Asdasdasdas",
            salt: "ASdasdas"
        }
    })



}
//add();








require('dotenv').config();

// Create the Express application
var app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

/**
 * -------------- DATABASE ----------------
 */


// Creates simple schema for a User.  The hash and salt are derived from the user's given password when they register



const strategy = new LocalStrategy(async function (username, password, cb) {
    console.log('strategy')
    const user = await prisma.user.findUnique({ where: { username: username } })

    if (!user) { return cb(null, false) }
    // Function defined at bottom of app.js
    console.log(user);
    const isValid = validPassword(password, user.hash, user.salt);

    if (isValid) {
        return cb(null, user);
    } else {
        return cb(null, false);
    }
})


passport.use(strategy);

passport.serializeUser(function (user, cb) {
    console.log('serialize')
    cb(null, user.id);
});


passport.deserializeUser(async function (id, cb) {
    console.log('deserialize');
    const user = await prisma.user.findUnique({ where: { id: id } })
    console.log(user);
    cb(null, user);
});


/**
 * -------------- SESSION SETUP ----------------
 */


app.use(session({
    //secret: process.env.SECRET,
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: {
        maxAge: 1000 * 60 * 60 * 24 // Equals 1 day (1 day * 24 hr/1 day * 60 min/1 hr * 60 sec/1 min * 1000 ms / 1 sec)
    }
}));





app.use(passport.initialize());
app.use(passport.session());



/**
 * -------------- ROUTES ----------------
 */

app.get('/', (req, res, next) => {
    const ff = path.join(__dirname, 'index.html');
    res.sendFile(ff);
});

app.get('/login', (req, res, next) => {

    const form = '<h1>Login Page</h1><form method="POST" action="/login">\
    Enter Username:<br><input type="text" name="username">\
    <br>Enter Password:<br><input type="password" name="password">\
    <br><br><input type="submit" value="Submit"></form>';

    res.send(form);

});

app.post('/login', passport.authenticate('local', { failureRedirect: '/login-failure', successRedirect: 'login-success' }), (err, req, res, next) => {
    console.log(req);
    if (err) next(err);
});

app.get('/register', (req, res, next) => {

    const form = '<h1>Register Page</h1><form method="post" action="register">\
                    Enter Username:<br><input type="text" name="username">\
                    <br>Enter Password:<br><input type="password" name="password">\
                    <br><br><input type="submit" value="Submit"></form>';

    res.send(form);

});

app.post('/register', async (req, res, next) => {
    const user1 = await prisma.user.findUnique({ where: { username: req.body.username } });
    console.log(user1);
    if (user1) {
        res.redirect('/register-failure');
        res.end();
    }
    else {
        const saltHash = genPassword(req.body.password);

        const salt = saltHash.salt;
        const hash = saltHash.hash;
        console.log(salt)
        const user = await prisma.user.create({
            data:
            {
                username: req.body.username,
                hash: hash,
                salt: salt
            }
        })

        res.redirect('/login');
    }


});

app.get('/protected-route', (req, res, next) => {

    // This is how you check if a user is authenticated and protect a route.  You could turn this into a custom middleware to make it less redundant
    if (req.isAuthenticated()) {
        res.send('<h1>You are authenticated</h1><p><a href="/logout">Logout and reload</a></p>');
    } else {
        res.send('<h1>You are not authenticated</h1><p><a href="/login">Login</a></p>');
    }
});

// Visiting this route logs the user out
app.get('/logout', (req, res, next) => {
    req.logout();
    res.redirect('/protected-route');
});

app.get('/login-success', (req, res, next) => {

    res.send('<p>You successfully logged in. --> <a href="/protected-route">Go to protected route</a></p>');
});

app.get('/login-failure', (req, res, next) => {
    res.send('You entered the wrong password.');
});
app.get('/register-failure', (req, res, next) => {
    res.send('This user already exists .');
});
// Server listens on http://localhost:3000
app.listen(3000);



function validPassword(password, hash, salt) {
    var hashVerify = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');
    return hash === hashVerify;
}

function genPassword(password) {
    var salt = crypto.randomBytes(32).toString('hex');
    var genHash = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');
    console.log(salt);
    return {
        salt: salt,
        hash: genHash
    };
}