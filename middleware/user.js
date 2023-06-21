import { isValidObjectId } from 'mongoose';
import User from '../Model/User.js';
import ResetToken from '../Model/ResetToken.js';

export const isValidResetToken = async (req, res, next) => {
  const { token, id } = req.query;
  if (!token || !id)
    return res.status(401).json({ success: false, error: 'invalid request' });
  if (!isValidObjectId(id))
    return res.status(401).json({ success: false, error: 'invalid user' });
  const user = await User.findById(id);
  if (!user)
    return res.status(401).json({ success: false, error: 'no user found' });
  const resetToken = await ResetToken.findOne({ owner: user._id });
  if (!resetToken)
    return res
      .status(401)
      .json({ success: false, error: 'reset token not found' });
  const validToken = await resetToken.compareResetToken(token);
  if (!validToken)
    return res
      .status(401)
      .json({ success: false, error: 'reset token is invalid' });
  req.user = user;
  next();
};
