const User = require('../models/user');
const jwt = require('jsonwebtoken');

module.exports.checkUser = async (req, res, next) => { 
    const token = req.cookies.jwt;
    if (token) {
        jwt.verify(token, process.env.JWT_SECRET, async (err, decoded) => { 
            if (err) {
                res.json({ status: false })
                next();
            }
            else {
                const user = await User.findById(decoded.id);
                if (user) {
                    res.json({ status: true, user: user });
                    next();
                }
                else { 
                    res.json({ status: false })
                    next();
                }
            }
        })
    }
    else {
        res.json({ status: false });
        next()
    }
}