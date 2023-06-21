import nodemailer from 'nodemailer';
import crypto from 'crypto';

export const generateOtp = () => {
  let otp = '';
  for (let i = 0; i <= 3; i++) {
    let val = Math.round(Math.random() * 9);
    otp += val;
  }
  return otp;
};

export const mailTransport = () => {
  var transport = nodemailer.createTransport({
    host: 'sandbox.smtp.mailtrap.io',
    port: 2525,
    auth: {
      user: process.env.MAILTRAP_ID,
      pass: process.env.MAILTRAP_PASS,
    },
  });
  return transport;
};

export const createRandomByte = () =>
  new Promise((resolve, reject) => {
    crypto.randomBytes(30, (err, buf) => {
      if (err) reject(err);
      const token = buf.toString('hex');
      resolve(token);
    });
  });
