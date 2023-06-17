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
      return res.status(400).json({ success, message: 'user already exist' });
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
    res.status(200).json({ success, message: 'successful', newUser });
  } catch (error) {
    console.error(error);
    console.error(error.message);
    res.status(500).send('some error occured while creating the user');
  }
};

export const LogIn = async (req, res) => {
  let success = false;
  let user = await User.findOne({ email: req.body.email });
  if (!user) {
    return res.status(400).json({ success, message: 'Incorrect Email' });
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
            return res
              .status(200)
              .json({ success, message: 'logged in', token: pass.token });
          } else {
            if (!err)
              return res
                .status(401)
                .json({ success, message: 'invalid credentials' });
          }
        });
      }
    });
  } catch (error) {
    res.status(401).json({ error: 'something went wrong' });
  }
};

export const verifyEmail = async (req, res) => {
  // Extract userId and otp from request body
  const { userId, otp } = req.body;

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
  console.log(user);

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
  const { email } = req.body;
  if (!email)
    return res
      .status(401)
      .json({ success: false, error: 'please provide email' });
  const user = await User.findOne({ email });
  if (!user)
    return res.status(401).json({ success: false, error: 'user not found!' });
  const checkToken = await ResetToken.findOne({ owner: user._id });
  if (checkToken) {
    return res.status(401).json({
      success: false,
      error:
        'new token will be generated after one hour of your previous request',
    });
  }
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
    html: `<div style="text-align:center"><h1>Reset Your password</h1> <a href='http://localhost:3000/reset-password?token=${token}&id=${user._id}'>Reset Password</a></div>`,
  });

  res.status(200).json({
    success: true,
    email: user.email,
    msg: 'reset link is set to your email id',
  });
};

export const resetPassword = async (req, res) => {
  const { password } = req.body;
  const user = await User.findById(req.user._id);
  if (!user)
    return res.status(401).json({ success: false, error: 'user not found' });
  const isSame = await user.comparePassword(password);
  if (isSame)
    return res
      .status(401)
      .json({ success: false, error: "you can't use your old password" });
  if (password.length < 5)
    return res
      .status(401)
      .json({ success: false, error: 'password too short' });
  user.password = password.trim();
  await user.save;
  await ResetToken.findOneAndDelete({ owner: user._id });
  mailTransport().sendMail({
    from: 'your-email@example.com',
    to: user.email,
    subject: 'password changed successfully',
    html: `<h1 style="text-align:center">your password is changed!</h1>`,
  });
  return res.status(200).json({
    success: true,
    email: user.email,
    msg: 'congrats your password is changed',
  });
};

//steps:user click on forget password
//steps:user provide their email
//
