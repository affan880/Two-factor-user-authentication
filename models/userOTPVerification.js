const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const bcrypt = require('bcrypt');

const userOTPVerificationSchema = new Schema({
    userId: {
        type: String,
        required: [true, 'User id is required'],
    },
    otp: {
        type: String,
        required: [true, 'OTP is required'],
    },
    createdAt: {
        type: Date,
        default: Date.now,
    },
    expiredAt: {
        type: Date,
    }
})

module.exports = mongoose.model('UserOTPVerification', userOTPVerificationSchema);