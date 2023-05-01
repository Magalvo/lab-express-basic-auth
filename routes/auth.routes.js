const router = require('express').Router();
const User = require('../models/User.model');
const bcrypt = require('bcryptjs');

router.get('/signup', (req, res) => {
  res.render('auth/signup');
});

router.post('/signup', async (req, res) => {
  const { username, password } = req.body;

  if (username === '' || password === '') {
    res.render('auth/signup', { errorMessage: 'Fill in all fields' });
    return;
  }

  const user = await User.findOne({ username });

  if (user !== null) {
    res.render('auth/signup', { errorMessage: 'User already exists' });
    return;
  }

  const saltRounds = 10;
  const salt = bcrypt.genSaltSync(saltRounds);
  const hashedPassword = bcrypt.hashSync(password, salt);
  await User.create({
    username,
    password: hashedPassword
  });
  res.redirect('/');
});

//-------------------------------------- LOGIN ---------------------------------//

router.get('/login', (req, res) => {
  res.render('auth/login');
});

router.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });

  try {
    if (!username || !password) {
      res.render('auth/login', { errorMessage: 'Invalid login' });
      return;
    }

    if (!user) {
      res.render('auth/login', { errorMessage: 'User does not exist' });
      return;
    }

    //check if password matches
    if (bcrypt.compareSync(password, user.password)) {
      req.session.currentUser = user;
      res.redirect('/');
    } else {
      res.render('auth/login', { errorMessage: 'Invalid login' });
      return;
    }
  } catch (err) {
    console.log(err);
  }
});
module.exports = router;
