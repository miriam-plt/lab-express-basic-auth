const mongoose = require('mongoose');
const { Router } = require('express');
const router = new Router();
const bcryptjs = require('bcryptjs');
const UserModel = require('../models/User.model');
const saltRounds = 10;

// GET route - display the signup form to users
router.get('/signup', (req, res) => res.render('auth/signup'));

// POST route - process form data
router.post('/signup', (req, res, next) => {
   // console.log('user signup data: ', req.body);
   const { username, email, password } = req.body;
   
   if (!username || !email || !password) {
    res.render('auth/signup', {errorMessage: 'All fields are mandatory. Please provide your username, email and password.'})
    return
   }

   const regex = /(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,}/;
   if (!regex.test(password)) {
    res
        .status(500)
        .render('auth/signup', {errorMessage: 'The password must be at least 6 characters, including one numerical character, one uppercase and one lowercase character.'})
        return;
   }    

 
   bcryptjs
     .genSalt(saltRounds)
     .then(salt => bcryptjs.hash(password, salt))
     .then(hashedPassword => {
       //console.log(`Password hash: ${hashedPassword}`);
       return UserModel.create({
        username,
        email,
        passwordHash: hashedPassword
       })
       .then(userFromDB => {
        // console.log('the new user is: ', userFromDB)
        res.redirect('/userProfile')
       })
     })
     .catch(error => { 
        if (error instanceof mongoose.Error.ValidationError) {
            res.status(500).render('auth/signup', {errorMessage: error.message})
        } else if (error.code === 11000) {
            res.status(500).render('auth/signup', {
                errorMessage: 'Username or email are already in use.'
            })
        } else {
            next(error);   
        } 
     })
})

router.get('/userProfile', (req, res) => {
    res.render('users/user-profile')
})

module.exports = router;
