const Joi = require('joi');


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

exports.validateLoginUser = validateLoginUser;
exports.validateUser = validateUser;
