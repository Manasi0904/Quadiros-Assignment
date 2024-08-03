const express = require('express');
const router = express.Router();
const User = require('../models/User');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { authenticateToken } = require('../middleware/auth');
const JWT_SECRET = 'manasi';//replace latter
const Car = require('../models/car');

// User login
router.get('/login', (req, res) => {
  res.render('user/login');
});

router.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });

  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.redirect('/user/login');
  }

  const token = jwt.sign({ id: user._id }, JWT_SECRET);
  res.cookie('token', token, { httpOnly: true });
  res.redirect('/user/cars');
});

// View Cars
router.get('/cars', authenticateToken, async (req, res) => {
  const cars = await Car.find();
  res.render('user/cars', { cars });
});

module.exports = router;
