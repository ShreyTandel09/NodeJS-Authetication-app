const express = require('express');
const router = express.Router();
const Joi = require('joi');
// const bcrypt = require('bcryptjs');
const User = require('../models/Users');

const app = express();


// Body parser middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));



const authController = require('../controllers/authController')

// Route for user registration
router.post('/register', authController.registerHandle);

// router.get('/verify-email/:token', authController.verifyEmail);

router.get('/verify-email', authController.verifyEmail);



module.exports = router;
