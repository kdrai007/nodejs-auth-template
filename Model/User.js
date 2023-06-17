import mongoose from 'mongoose';
import bcrypt from 'bcrypt';

const userSechma = mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  token: { type: String },
  date: { type: Date, default: Date.now() },
  verified: { type: Boolean, default: false, required: true },
});

userSechma.methods.comparePassword = async function (password) {
  const result = bcrypt.compareSync(password, this.password);
  return result;
};

const User = mongoose.model('User', userSechma);

export default User;
