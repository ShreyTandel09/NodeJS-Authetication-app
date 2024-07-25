require('dotenv').config();
const jwt = require('jsonwebtoken');


function generateToken(user, emailToken) {
    const options = {};

    const payload = {
        email: user.email,
        name: user.name,
        uniqueKey: process.env.UNIQUE_KEY
    };
    if (emailToken) {
        options.expiresIn = '1h';
    }
    return jwt.sign(payload, process.env.JWT_SECRET, options);

}


function generateRefreshToken(user) {
    const options = {};

    const payload = {
        email: user.email,
        name: user.name,
        uniqueKey: process.env.UNIQUE_KEY
    };

    return jwt.sign(payload, process.env.REFRESH_TOKEN_SECRET, { expiresIn: '7d' });

}


exports.generateToken = generateToken;
exports.generateRefreshToken = generateRefreshToken;