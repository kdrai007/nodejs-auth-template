import mongoose from 'mongoose';
import bcrypt from 'bcrypt';

const verficatonTokenSchema = mongoose.Schema({
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
    expires: 3600,
    default: Date.now(),
  },
});

verficatonTokenSchema.methods.compareToken = async function (token) {
  const result = bcrypt.compareSync(token, this.token);
  return result;
};
export const Vtoken = mongoose.model('verification', verficatonTokenSchema);

// ('save', function (next) {
//   if (this.isModified('token')) {
//     const hash = bcrypt.hash(this.token, 8);
//     this.token = hash;
//   }
//   next();
// });
