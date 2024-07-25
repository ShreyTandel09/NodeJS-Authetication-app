const Joi = require('joi');
const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const emailService = require('../config/email')
const jwt = require('jsonwebtoken');
const User = require('../models/Users');
const RefreshToken = require('../models/RefreshToken');



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
            return res.status(400).json({ error: 'User already exists' });
        }

        // // Create a new user
        user = new User({ name, email, password });

        // // Hash the password
        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(password, salt);

        // Save the user to the database
        const userData = await user.save();
        //verification Email
        emailService.sendEmailVerification(user)
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
    const { email } = decodedToken;

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


exports.loginHandle = async (req, res) => {

    const { email, password } = req.body;
    const { error } = validateLoginUser(req.body);
    if (error) {
        return res.status(400).json({ error: error.details[0].message });
    }

    let user = await User.findOne({ email });
    if (!user) {
        return res.status(400).json({ error: 'Please Register!!' });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
        return res.status(400).json({ error: 'Invalid password!' });
    }
    //token and refresh token
    const token = emailService.generateToken(user)
    const refreshToken = emailService.generateRefreshToken(user)
    await new RefreshToken({ token: refreshToken, userId: user._id }).save();
    res.status(200).json({
        message: 'User login successful',
        user: user,
        token: token,
        refreshToken: refreshToken
    });

}



exports.refreshTokenHandle = (async (req, res) => {
    const { refreshToken } = req.body;
    if (!refreshToken) {
        return res.status(401).json({ error: 'Refresh token is required' });
    }

    const refreshTokenDoc = await RefreshToken.findOne({ token: refreshToken });
    if (!refreshTokenDoc) {
        return res.status(401).json({ error: 'Invalid refresh token' });
    }

    const user = await User.findById(refreshTokenDoc.userId);
    if (!user) {
        return res.status(401).json({ error: 'User not found' });
    }

    const newAccessToken = emailService.generateToken(user);
    // res.status(200).json({ token: newAccessToken });

    res.status(200).json({
        message: 'New token Generated',
        user: user,
        token: newAccessToken,
        refreshToken: refreshToken
    })
});



// Function to validate user Login input
function validateLoginUser(user) {
    const schema = Joi.object({
        email: Joi.string().email().required(),
        password: Joi.string().min(6).required(),
    });

    return schema.validate(user);
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

