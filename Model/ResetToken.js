import mongoose from 'mongoose';
import bcrypt from 'bcrypt';

const resetTokenSchema = mongoose.Schema({
  owner: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
  },
  token: {
    type: String,
    required: true,
  },
  creatdAt: {
    type: Date,
    expires: 7200,
    default: Date.now(),
  },
});

resetTokenSchema.methods.compareResetToken = async function (token) {
  const result = bcrypt.compareSync(token, this.token);
  return result;
};
const ResetToken = mongoose.model('resetToken', resetTokenSchema);

export default ResetToken;

// ('save', function (next) {
//   if (this.isModified('token')) {
//     const hash = bcrypt.hash(this.token, 8);
//     this.token = hash;
//   }
