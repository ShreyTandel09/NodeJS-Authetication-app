const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const emailService = require('../utils/email')
const jwtToken = require('../utils/JWTtoken')
const jwt = require('jsonwebtoken');
const User = require('../models/Users');
const RefreshToken = require('../models/RefreshToken');
const { generateToken, generateRefreshToken } = require('../utils/JWTtoken');
const { validateUser, validateLoginUser } = require('../validation/userValidation');
const passport = require('passport');



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


// exports.loginHandle = async (req, res) => {

//     try {
//         const { email, password } = req.body;
//         const { error } = validateLoginUser(req.body);
//         if (error) {
//             return res.status(400).json({ error: error.details[0].message });
//         }

//         let user = await User.findOne({ email });
//         if (!user) {
//             return res.status(400).json({ error: 'Please Register!!' });
//         }

//         const validPassword = await bcrypt.compare(password, user.password);
//         if (!validPassword) {
//             return res.status(400).json({ error: 'Invalid password!' });
//         }

//         if (!user.isVerified) {
//             return res.status(400).json({ error: 'Please verify your email!' });
//         }
//         //token and refresh token
//         const token = generateToken(user)
//         const refreshToken = generateRefreshToken(user)
//         await new RefreshToken({ token: refreshToken, userId: user._id }).save();
//         res.status(200).json({
//             message: 'User login successful',
//             user: user,
//             token: token,
//             refreshToken: refreshToken
//         });
//     } catch (error) {
//         console.error(error.message);
//         res.status(500).json({ error: 'Server error' });
//     }

// }


exports.loginHandle = async (req, res, next) => {

    try {
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

        if (!user.isVerified) {
            return res.status(400).json({ error: 'Please verify your email!' });
        }


        req.logIn(user, err => {
            if (err) return next(err);
            return res.status(200).json({ message: 'User login successful', user });
        });



    } catch (error) {
        console.error(error.message);
        res.status(500).json({ error: 'Server error' });
    }

}





exports.refreshTokenHandle = async (req, res) => {

    try {
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

        const newAccessToken = generateToken(user);
        // res.status(200).json({ token: newAccessToken });

        res.status(200).json({
            message: 'New token Generated',
            user: user,
            token: newAccessToken,
            refreshToken: refreshToken
        })
    } catch (error) {
        console.error(err.message);
        res.status(500).json({ error: 'Server error' });
    }

};

exports.forgotPassword = async (req, res) => {
    try {

        const { email } = req.body;
        if (!email) {
            return res.status(401).json({ error: 'Email is Required' });
        }
        let user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ error: 'User with Email ID does not exist!!' });
        }

        //verification Email
        emailService.sendRestEmail(user)
        res.status(201).json({
            message: 'Password reset email sent',
        });
    } catch (error) {
        console.error(err.message);
        res.status(500).json({ error: 'Server error' });
    }

}

exports.resetPassword = async (req, res) => {
    try {
        const { token, password } = req.body;
        const decodedToken = jwt.verify(token, process.env.JWT_SECRET);
        const { email } = decodedToken;

        let user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ error: 'Invalid or expired token' });
        }

        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(password, salt);
        await user.save();

        res.status(200).json({ message: 'Password reset successful' });
    } catch (error) {
        console.error(error.message);
        res.status(500).json({ error: 'Server error' });
    }
}

exports.getUserProfileInfo = async (req, res) => {
    try {
        const user = await User.findById(req.user.id);
        if (!user) {
            return res.status(400).json({ error: 'User not found' });
        }
        res.status(200).json({ user });
    } catch (error) {
        console.error(error.message);
        res.status(500).json({ error: 'Server error' });
    }
}



