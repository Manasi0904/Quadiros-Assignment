const express = require('express');
const router = express.Router();
const User = require('../models/User');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { authenticateToken, authorizeRole } = require('../middleware/auth');
const JWT_SECRET = 'manasi';//replace with env latter
const Car = require('../models/car');

// Admin login
router.get('/login', (req, res) => {
  res.render('admin/login');
});

router.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });

  if (!user || !(await bcrypt.compare(password, user.password))) {

    return res.redirect('/admin/login');
  }

  if (user.role !== 'admin') {
    return res.redirect('/admin/login');
  }

  const token = jwt.sign({ id: user._id }, JWT_SECRET);
  res.cookie('token', token, { httpOnly: true });
  res.redirect('/admin/dashboard');
});

// Dashboard
router.get('/dashboard', authenticateToken, authorizeRole('admin'), async (req, res) => {
  const cars = await Car.find();
  const totalCars = cars.length;
  res.render('admin/dashboard', { cars, totalCars });
});

// Create Car
router.post('/cars', authenticateToken, authorizeRole('admin'), async (req, res) => {
  const { carName, manufacturingYear, price } = req.body;
  const car = new Car({ carName, manufacturingYear, price });
  await car.save();
  res.redirect('/admin/dashboard');
});

// Update Car
router.post('/cars/:id/update', authenticateToken, authorizeRole('admin'), async (req, res) => {
  const { id } = req.params;
  const { carName, manufacturingYear, price } = req.body;
  await Car.findByIdAndUpdate(id, { carName, manufacturingYear, price });
  res.redirect('/admin/dashboard');
});

// Delete Car
router.post('/cars/:id/delete', authenticateToken, authorizeRole('admin'), async (req, res) => {
  const { id } = req.params;
  await Car.findByIdAndDelete(id);
  res.redirect('/admin/dashboard');
});

module.exports = router;
