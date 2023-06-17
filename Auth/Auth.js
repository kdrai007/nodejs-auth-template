import express from 'express';
import {
  LogIn,
  SignUp,
  forgotPassword,
  verifyEmail,
  resetPassword,
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

//http://localhost:5555/api/reset-password to call this api

Router.post('/forgot-password', forgotPassword);
//http://localhost:5555/api/reset-password to call this api

Router.post('/forgot-password', isValidResetToken, resetPassword);

export default Router;