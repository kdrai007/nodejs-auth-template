import bcrypt from 'bcrypt';
import User from '../../Model/User.js';
import jwt from 'jsonwebtoken';
import {
  createRandomByte,
  generateOtp,
  mailTransport,
} from '../../utils/helpers.js';
import { isValidObjectId } from 'mongoose';
import { Vtoken } from '../../Model/verifyUser.js';
import ResetToken from '../../Model/ResetToken.js';
const saltRound = 10;

export const SignUp = async (req, res) => {
  try {
    let success = false;
    let user = await User.findOne({ email: req.body.email });
    if (user) {
      return res.status(400).json({ success, error: 'user already exist' });
    }

    const { name, email, password } = req.body;
    const salt = await bcrypt.genSalt(saltRound);
    const hash = await bcrypt.hash(password, salt);
    const newUser = new User({
      name: name,
      email: email.toLowerCase(),
      password: hash,
    });
    //for verification of user
    const OTP = generateOtp();
    const hashOTP = await bcrypt.hash(OTP, 8);
    const verificationToken = new Vtoken({
      owner: newUser._id,
      token: hashOTP,
    });

    const token = jwt.sign(
      { user_id: newUser._id, email },
      process.env.TOKEN_KEY,
      {
        expiresIn: '2h',
      }
    );
    newUser.token = token;
    await newUser.save();
    await verificationToken.save();

    mailTransport().sendMail({
      from: 'verficationByKd@email.com',
      to: newUser.email,
      subject: 'Vefify your email account',
      html: `<h1>${OTP}</h1>`,
    });

    success = true;
    res
      .status(200)
      .json({ success, message: 'successful', user: newUser.name, token });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'some error occured while creating the user',
    });
  }
};

export const LogIn = async (req, res) => {
  let success = false;
  let user = await User.findOne({ email: req.body.email });
  if (!user) {
    return res.status(400).json({ success, error: 'Incorrect Email' });
  }
  try {
    const { email, password } = req.body;
    User.findOne({ email: email }, (err, pass) => {
      if (!err) {
        bcrypt.compare(password, pass.password, function (err, result) {
          if (result) {
            const token = jwt.sign(
              { user_id: pass._id, email },
              process.env.TOKEN_KEY,
              {
                expiresIn: '2h',
              }
            );
            // save user token
            pass.token = token;

            success = true;
            return res.status(200).json({
              success,
              message: 'logged in',
              token: pass.token,
              user: pass.name,
            });
          } else {
            if (!err)
              return res
                .status(401)
                .json({ success, error: 'invalid credentials' });
          }
        });
      }
    });
  } catch (error) {
    res.status(401).json({ success: false, error: 'something went wrong' });
  }
};

export const genrateVerificationToken = async (req, res) => {
  const { id } = req.query;
  if (!id)
    return res.status(401).json({ success: false, error: 'no user id found' });
  const user = await User.findById(id).select('-password');
  if (!user)
    return res.status(400).json({ success: false, error: 'no user found' });
  if (user.verified)
    return res
      .status(401)
      .json({ success: false, error: 'user is already verified' });
  const token = await Vtoken.findOne({ owner: user._id });
  if (token)
    return res.status(400).json({
      success: false,
      error: 'token is already generated! check your email',
    });
  const OTP = generateOtp();
  const hashOTP = await bcrypt.hash(OTP, 8);
  const verificationToken = new Vtoken({
    owner: user._id,
    token: hashOTP,
  });
  await verificationToken.save();
  mailTransport().sendMail({
    from: 'verficationByKd@email.com',
    to: user.email,
    subject: 'Vefify your email account',
    html: `<h1>${OTP}</h1>`,
  });
  res
    .status(200)
    .json({ success: true, msg: 'new token is generated!check your email' });
};

export const verifyEmail = async (req, res) => {
  // Extract userId and otp from request body
  const { userId, otp } = req.body;
  console.log(userId);
  console.log(otp);
  // Check if userId or otp is missing or empty
  if (!userId || !otp.trim()) {
    return res.status(401).json({ success: false, error: 'Invalid request!' });
  }
  // Check if userId is a valid ObjectId
  if (!isValidObjectId(userId)) {
    return res.status(401).json({ success: false, error: 'Invalid User Id!' });
  }
  // Find the user by the userId
  const user = await User.findById(userId);
  // Check if user exists
  if (!user) {
    return res.status(401).json({ success: false, error: 'No users found!' });
  }
  // Check if user is already verified
  if (user.verified) {
    return res
      .status(401)
      .json({ success: false, error: 'User is already verified' });
  }
  // Find the verification token associated with the user
  const token = await Vtoken.findOne({ owner: user._id });
  // Check if verification token exists
  if (!token) {
    return res.status(401).json({ success: false, error: 'No token found' });
  }
  // Compare the provided OTP with the stored token
  const isMatched = await token.compareToken(otp);
  // Check if the OTP matches
  if (!isMatched) {
    return res
      .status(401)
      .json({ success: false, error: 'Please provide a valid token' });
  }
  // Update the user as verified
  user.verified = true;
  // Delete the verification token
  await Vtoken.findByIdAndDelete(token._id);
  // Save the updated user
  await user.save();
  // Send verification email
  mailTransport().sendMail({
    from: 'your-email@example.com',
    to: user.email,
    subject: 'Your Verification',
    html: `<h1 style="text-align:center">Your email is verified!</h1>`,
  });
  // Return success response
  res.status(200).json({ success: true, msg: 'User verified' });
};

export const forgotPassword = async (req, res) => {
  //destructuring email from req.body;
  const { email } = req.body;
  //checking if email is not null
  if (!email)
    return res
      .status(401)
      .json({ success: false, error: 'please provide email' });
  //finding user from given email id
  const user = await User.findOne({ email });
  //checking if user exist or not by given email by
  if (!user)
    return res.status(401).json({ success: false, error: 'user not found!' });
  //checking if there is is any old token to same user
  const checkToken = await ResetToken.findOne({ owner: user._id });
  if (checkToken) {
    return res.status(401).json({
      success: false,
      error:
        'new token will be generated after one hour of your previous request',
    });
  }
  //creating new token and hashing it with bcrypt
  const token = await createRandomByte();
  const hashToken = await bcrypt.hash(token, 8);
  const resetToken = new ResetToken({
    owner: user._id,
    token: hashToken,
  });
  await resetToken.save();

  // Send verification email
  mailTransport().sendMail({
    from: 'your-email@example.com',
    to: user.email,
    subject: 'Reset password',
    html: `<div style="text-align:center"><h1>Reset Your password</h1> <a href='http://localhost:5173/reset-password?token=${token}&id=${user._id}'>Reset Password</a></div>`,
  });
  //sucessfull message
  res.status(200).json({
    success: true,
    email: user.email,
    msg: 'reset link is set to your email id',
  });
};

export const resetPassword = async (req, res) => {
  //destructuring password from req.body
  const { password } = req.body;
  // finding user from database with user._id
  const user = await User.findById(req.user._id);
  //checking if user exist or not
  if (!user)
    return res.status(401).json({ success: false, error: 'user not found' });
  //checking if password is same old
  const isSame = await user.comparePassword(password);
  if (isSame)
    return res
      .status(401)
      .json({ success: false, error: "you can't use your old password" });
  //checking password length
  if (password.length < 5)
    return res
      .status(401)
      .json({ success: false, error: 'password too short' });
  //storing new password in user database
  const hashedPassword = await bcrypt.hash(password, 8);
  user.password = hashedPassword;
  await user.save();
  //deleting the resetToken
  await ResetToken.findOneAndDelete({ owner: user._id });
  //sending mail to user's email id
  mailTransport().sendMail({
    from: 'your-email@example.com',
    to: user.email,
    subject: 'password changed successfully',
    html: `<h1 style="text-align:center">your password is changed!</h1>`,
  });
  //successfull message
  return res.status(200).json({
    success: true,
    email: user.email,
    msg: 'congrats your password is changed',
  });
};
