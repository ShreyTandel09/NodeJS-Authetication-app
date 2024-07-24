require('dotenv').config();
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');


function sendEmailVerification(user) {
    const token = generateToken(user, emailToken = true);

    console.log("TOKEN in EMAIL");
    console.log(token);
    const html = getVerificationEmailHTML(user, token);
    // Create a transporter object using the default SMTP transport
    let transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: process.env.MAIL_FROM_ADDRESS, // Replace with your email
            pass: process.env.MAIL_PASSWORD // Replace with your email password
        }
    });

    // Email options
    const mailOptions = {
        from: process.env.MAIL_FROM_ADDRESS,
        to: user.email,
        subject: 'Verify Your Email',
        text: `Hi ${user.name}, please verify your email by clicking the following link: ${process.env.FRONTEND_URL}/auth/verify-email?token=${token}`,
        html: html
    };

    // Send email
    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            return console.log(`Error: ${error}`);
        }
        console.log(`Message Sent: ${info.response}`);
    });


}


function getVerificationEmailHTML(user, token) {
    const verificationLink = `${process.env.FRONTEND_URL}/auth/verify-email?token=${token}`;

    return `
        <h1>Email Verification</h1>
        <p>Hi ${user.name},</p>
        <p>Thank you for registering. Please click the link below to verify your email address:</p>
        <a href="${verificationLink}">Verify Email</a>
        <p>If you did not register for this account, please ignore this email.</p>
    `;
}

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





exports.sendEmailVerification = sendEmailVerification;
exports.generateToken = generateToken;