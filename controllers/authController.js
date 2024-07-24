const Joi = require('joi');
const express = require('express');
const router = express.Router();
const User = require('../models/Users');
const bcrypt = require('bcryptjs');
const emailService = require('../config/email')
const jwt = require('jsonwebtoken');


exports.registerHandle = async (req, res) => {

    const { error } = validateUser(req.body);
    if (error) {
        return res.status(400).json({ error: error.details[0].message });
    }

    const { name, email, password } = req.body;

    try {
        // Check if the user already exists
        let user = await User.findOne({ email });
        if (user) {
            const email = emailService.sendEmailVerification(user)
            return res.status(400).json({ error: 'User already exists' });
        }

        // // Create a new user
        user = new User({ name, email, password });

        // // Hash the password
        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(password, salt);

        // Save the user to the database
        const userData = await user.save();

        // Send a success response
        res.status(201).json({
            message: 'User registration successful',
            user: userData
        });
    } catch (err) {
        console.error(err.message);
        res.status(500).json({ error: 'Server error' });
    }
}



exports.verifyEmail = async (req, res) => {
    const { token } = req.query;
    const decodedToken = jwt.verify(token, process.env.JWT_SECRET);
    const { name, email } = decodedToken;

    try {
        let user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ error: 'Invalid or expired token' });
        }
        //user is verified here
        user.isVerified = true;
        await user.save();

        res.status(200).json({ message: 'Email verified successfully' });
    } catch (err) {
        console.error(err.message);
        res.status(500).json({ error: 'Server error' });
    }
}

// Helper function to get a User
async function getUser(id) {
    return await User.findById(id);
}


// Function to validate user input
function validateUser(user) {
    const schema = Joi.object({
        name: Joi.string().min(3).required(),
        email: Joi.string().email().required(),
        password: Joi.string().min(6).required(),
        confirmPassword: Joi.string().valid(Joi.ref('password')).required().messages({
            'any.only': 'Confirm Password must match the Password'
        })
    });

    return schema.validate(user);
}

