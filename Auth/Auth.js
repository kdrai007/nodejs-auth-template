import express from 'express';
import {
  LogIn,
  SignUp,
  forgotPassword,
  verifyEmail,
  resetPassword,
  genrateVerificationToken,
} from './controllers/AuthFunctions.js';
import { validateUser, validate } from '../middleware/validator.js';
import { isValidResetToken } from '../middleware/user.js';
const Router = express.Router();

//http://localhost:5555/api/singup to call this api
Router.post('/signup', validateUser, validate, SignUp);

//http://localhost:5555/api/login to call this api
Router.post('/login', LogIn);

//http://localhost:5555/api/verify-email to call this api

Router.post('/verify-email', verifyEmail);
//http://localhost:5555/api/verify-email to call this api

Router.get('/check-verificationtoken', genrateVerificationToken);

//http://localhost:5555/api/forgot-password to call this api

Router.post('/forgot-password', forgotPassword);
//http://localhost:5555/api/reset-password to call this api

Router.post('/reset-password', isValidResetToken, resetPassword);

//http://localhost:5555/api/verify-token to call this api
Router.get('/verify-token', isValidResetToken, (req, res) => {
  res.status(200).json({ success: true, msg: 'your token is verified' });
});

export default Router;
