const userSchema = require("../models/user");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const maxAge = 3 * 24 * 60 * 60;
const bcrypt = require("bcrypt");
const createToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: maxAge,
  });
};
const UserOTPVerification = require("../models/userOTPVerification");
let transporter = nodemailer.createTransport({
  service: "gmail",
  host: "smtp.gmail.com",
  auth: {
    type: "OAuth2",
    user: process.env.MAIL_USERNAME,
    pass: process.env.MAIL_PASSWORD,
    clientId: process.env.OAUTH_CLIENTID,
    clientSecret: process.env.OAUTH_CLIENT_SECRET,
    refreshToken: process.env.OAUTH_REFRESH_TOKEN
  },
});
const handleError = (err) => {
    let errors = { email: "", username: "", password: "" };
    if (err.message === "Invalid email") { 
        errors.email = "That email is not registered";
    }
    if (err.message === "Invalid password") {
        errors.password = "Invalid password";
    }
      if (err.code === 11000) {
        errors.email = "Email has been used before";
        errors.username = "Invalid username";
        errors.password = "Password is required";
        return errors;
      }
       if (err.message.includes("Users validation failed")) {
         Object.values(err.errors).forEach(({ properties }) => {
           errors[properties.path] = properties.message;
         });
    }
    return errors;
 }

module.exports.login = async (req, res, next) => { 
    try {
        const email = req.body.email;
        const password = req.body.password;
        const user = await userSchema.login(email, password);
        const token = createToken(user._id);
        res.cookie("jwt", token, {
          withCredentials: true,
          httpOnly: false,
          maxAge: maxAge * 1000,
        });
        res.status(201).json({ user: user._id, created: true });
      } catch (err) {
        console.log(err);
        const errors = handleError(err);
        res.json({ errors, created: false });
      }
 }
module.exports.register = async (req, res, next) => {
  try {
    await userSchema.create({
        email: req.body.email,
        username: req.body.username,
        password: req.body.password,
        verified: false,
      }).then((user) => { 
        const email = user.email;
        const _id = user._id;
        verifyOTP({_id, email}, res);
      })
    }
    catch (err) { 
        const errors = handleError(err);
        res.json({errors, created:false});
    }
};
 
 
const verifyOTP = async ({_id, email}, res) => {
  try {
    const otp = `${Math.floor(1000 + Math.random() * 9000)}`;
    const mailOptions = {
      from: process.env.MAIL_USERNAME,
      to: email,
      subject: "OTP Verification",
      text: `Your OTP is ${otp}`,
    };

    const saltRounds = 10;
    const hashedOTP = await bcrypt.hash(otp, saltRounds);
    const token = createToken(_id);
    res.cookie("jwt", token, {
        withCredentials: true,
        httpOnly: false,
        maxAge: maxAge * 1000,
    });

    const newOTPVerification = new UserOTPVerification({
      userId: _id,
      otp: hashedOTP,
      createdAt: Date.now(),
      expiredAt: Date.now() + 3600000,
    });
    await newOTPVerification.save();
    transporter.sendMail(mailOptions);
    res.json({
      status: true,
      message: "OTP has been sent to your email",
      data: {
        userId: _id,
        email,
      },
    });
  }
    catch (err) {
    res.json({ 
      status: "FAILED",
      message: err.message,
       });
    }
}

module.exports.verifyOTP = async (req, res, next) => {
  try {
    const userId = req.body.userId;
    const otp = req.body.otp;
    if (!userId || !otp) {
      res.json({
        status: false,
        message: "UserId and OTP are required",
      });
    }
    else {
      const userOTPVerificationRecord = await UserOTPVerification.find({
        userId
      });
      if (userOTPVerificationRecord.length <= 0) {
        res.json({
          status: false,
          message: "Account doesn't exist or has been verified",
        });
      }
      else {
        const { expiredAt } = userOTPVerificationRecord[0];
        const hashedOTP = userOTPVerificationRecord[0].otp;

        if (expiredAt < Date.now() ) {
          await UserOTPVerification.deleteMany({ userId });
          throw new Error("OTP has been expired");
        }
        else {
          const validOTP = await bcrypt.compare(otp, hashedOTP);
          console.log(validOTP);
          if (!validOTP) {
            threwow(new Error("Invalid OTP"));
          }
          else {
            await userSchema.updateOne({ _id: userId},{ verified: true });
            await UserOTPVerification.deleteMany({ userId })
            res.json({
              status: "VERIFIED",
              message: "email is verified",
            })
          }
        }
      }
    } 
  }
  catch (err) {
      res.json({
        status: "FAILED",
        message: err.message,
      });
    }
}
  
module.exports.resendOTP = async (req, res, next) => { 
  try {
    const { userId, email } = req.body;
    if (!userId || !email) {
      res.json({
        status: false,
        message: "UserId and email are required",
      });
    }
    else { 
      await UserOTPVerification.deleteMany({ userId });
      verifyOTP({ _id: userId, email }, res);
    }
  }
  catch (err) { 
    res.json({
      status: "FAILED",
      message: err.message,
    });
  }
}

module.exports.logout = async (req, res, next) => {
  try {
    res.clearCookie("jwt");
    res.json({
      status: true,
      message: "Logout successfully",
    });
  }
  catch (err) {
    res.json({
      status: "FAILED",
      message: err.message,
    });
  }
}

module.exports.resetPassword = async (req, res, next) => {
  try {
    const { email } = req.body;
    if (!email) {
      res.json({
        status: false,
        message: "Email is required",
      });
    }
    else { 
      const userDetailsRecord = await userSchema.findOne({ email });
      if (!userDetailsRecord) {
        res.json({
          status: false,
          message: "Account doesn't exist",
        });
      }
      else { 
        const otp = `${Math.floor(1000 + Math.random() * 9000)}`;
        const mailOptions = {
          from: process.env.MAIL_USERNAME,
          to: email,
          subject: "OTP Verification",
          text: `Your OTP is ${otp}`,
        };
        const saltRounds = 10;
        const hashedOTP = await bcrypt.hash(otp, saltRounds);
        const newOTPVerification = new UserOTPVerification({
          userId: userDetailsRecord._id,
          otp: hashedOTP,
          createdAt: Date.now(),
          expiredAt: Date.now() + 3600000,
        });
        await newOTPVerification.save();
        transporter.sendMail(mailOptions);
        res.json({
          status: true,
          message: "OTP has been sent to your email",
          data: {
            userId: userDetailsRecord._id,
            email,
          },
        });
      }
    }
  }
  catch (err) {
    res.json({
      status: "FAILED",
      message: err.message,
    });
   } 
}

module.exports.changePassword = async (req, res, next) => {
  try {
    const { userId, otp, newPassword } = req.body;
    if (!userId || !otp || !newPassword) {
      res.json({
        status: false,
        message: "UserId, OTP and new password are required",
      });
    }
    else { 
      const userOTPVerificationRecord = await UserOTPVerification.find({
        userId
      });
      if (userOTPVerificationRecord.length <= 0) {
        res.json({
          status: false,
          message: "Account doesn't exist or has been verified",
        });
      }
      else {
        const { expiredAt } = userOTPVerificationRecord[0];
        const hashedOTP = userOTPVerificationRecord[0].otp;

        if (expiredAt < Date.now() ) {
          await UserOTPVerification.deleteMany({ userId });
          throw new Error("OTP has been expired");
        }
        else {
          const validOTP = await bcrypt.compare(otp, hashedOTP);
          if (!validOTP) {
            throw new Error("Invalid OTP");
          }
          else {
            const saltRounds = 10;
            const hashedPassword = await bcrypt.hash(newPassword, saltRounds);
            await userSchema.updateOne({ _id: userId},{ password: hashedPassword });
            await UserOTPVerification.deleteMany({ userId })
            res.json({
              status: true,
              message: "Password has been changed",
            })
          }
        }
      }
    }
  }
  catch (err) {
    res.json({
      status: "FAILED",
      message: err.message,
    });
  }
}