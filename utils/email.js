require('dotenv').config();
const nodemailer = require('nodemailer');
const jwtToken = require('./JWTtoken');



function sendEmailVerification(user) {
    const token = jwtToken.generateToken(user, emailToken = true);

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


function sendRestEmail(user) {
    const token = jwtToken.generateToken(user, emailToken = true);

    const html = getRestEmailHTML(user, token);
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
        subject: 'Reset Your Password',
        text: `Hi ${user.name}, please reset your password by clicking the following link: ${process.env.FRONTEND_URL}/auth/reset-password?token=${token}`,
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


function getRestEmailHTML(user, token) {
    const verificationLink = `${process.env.FRONTEND_URL}/auth/reset-password?token=${token}`;

    return `
        <h1>Reset Password</h1>
        <p>Hi ${user.name},</p>
        <p> Please click the link below to reset password:</p>
        <a href="${verificationLink}">Reset password</a>
        <p>If you did not register for this account, please ignore this email.</p>
    `;
}

exports.sendEmailVerification = sendEmailVerification;
exports.sendRestEmail = sendRestEmail;
