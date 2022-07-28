const mongoose = require('mongoose');
const becrypt = require('bcrypt');
const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: [true, 'Email has been used before'],
    unique: true,
  },
  username: {
    type: String,
    required: [true, 'Invalid username'],
    unique: true,
    minlength: 5,
  },
  password: {
    type: String,
    required: [true, 'Password is required'],
    minlength: 8,
  },
  verified: {
    type: Boolean,
  }
})

userSchema.pre('save', async function (next) {
  const salt = await becrypt.genSalt();
  this.password = await becrypt.hash(this.password, salt);
  next();
})
 
userSchema.statics.login = async function (email, password) { 
  const user = await this.findOne({ email });
  if (user) {
    const auth = await becrypt.compare(password, user.password);
    if (auth) {
      return user;
    }
    throw Error('Invalid password');
  }
  throw Error('Invalid email');
}

module.exports = mongoose.model('Users', userSchema);