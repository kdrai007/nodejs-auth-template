import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
dotenv.config();

const config = process.env;

const verifyToken = (req, res, next) => {
  const token =
    req.body.token || req.query.token || req.headers['access-token'];

  if (!token) {
    return res
      .status(403)
      .json({ success: false, msg: 'A token is required for authentication' });
  }
  try {
    const decoded = jwt.verify(token, config.TOKEN_KEY);
    req.user = decoded;
  } catch (err) {
    return res.status(401).json({ success: false, msg: 'Invalid Token' });
  }
  return next();
};

export default verifyToken;
