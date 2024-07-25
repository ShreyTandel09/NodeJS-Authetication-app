require('dotenv').config();
const jwt = require('jsonwebtoken');
const User = require('../models/Users');

exports.isAuthenticated = async (req, res, next) => {
    // Get token from the Authorization header
    const token = req.headers['authorization'];

    console.log("token:", token);

    if (!token) return res.status(401).json({ error: 'No token provided' });

    try {
        // Verify the token
        const decodedToken = jwt.verify(token, process.env.JWT_SECRET);
        // Use the correct field based on your schema
        const userId = decodedToken.id;
        const user = await User.findOne({ _id: userId });
        if (!user) {
            return res.status(401).json({ error: 'User not found' });
        }
        req.user = user;
        next(); // Pass control to the next middleware or route handler
    } catch (err) {
        console.error("Error:", err);
        res.status(403).json({ error: 'Invalid or expired token' });
    }
};
