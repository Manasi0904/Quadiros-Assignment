const jwt = require('jsonwebtoken');
const User = require('../models/User');
const JWT_SECRET = 'manasi';//replace latter with env

const authenticateToken = (req, res, next) => {
  const token = req.cookies.token || '';
  if (!token) return res.redirect('/login');

  jwt.verify(token, JWT_SECRET, async (err, user) => {
    if (err) return res.redirect('/login');
    req.user = await User.findById(user.id);
    next();
  });
};

const authorizeRole = (role) => (req, res, next) => {
  if (req.user.role !== role) return res.redirect('/login');
  next();
};

module.exports = { authenticateToken, authorizeRole };