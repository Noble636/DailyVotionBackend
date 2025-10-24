const nodemailer = require('nodemailer');
const { google } = require('googleapis');

const CLIENT_ID = process.env.GMAIL_CLIENT_ID || '774066233483-o8hvoj1smb67ldf20pmhhl3rouf5d5c2.apps.googleusercontent.com';
const CLIENT_SECRET = process.env.GMAIL_CLIENT_SECRET || 'GOCSPX-BTwZplaenbxw41Vig_E5uxH1hQZ';
const REDIRECT_URI = process.env.GMAIL_REDIRECT_URI || 'https://developers.google.com/oauthplayground';
const REFRESH_TOKEN = process.env.GMAIL_REFRESH_TOKEN || '1//04ffKPYVM_fgmCgYIARAAGAQSNwF-L9IrzAsQIzS_BVd1d0_TjP58IV0JWuyFySxECfkjPvI5s9Uh612DCa7ej3I10I_RhRjmVUU';
const SENDER = process.env.GMAIL_SENDER || 'dailyvotion4b@gmail.com';

const oAuth2Client = new google.auth.OAuth2(
  CLIENT_ID,
  CLIENT_SECRET,
  REDIRECT_URI
);
oAuth2Client.setCredentials({ refresh_token: REFRESH_TOKEN });

async function sendOTPEmail(to, otp) {
  try {
    const accessToken = await oAuth2Client.getAccessToken();
    const transport = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        type: 'OAuth2',
        user: SENDER,
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        refreshToken: REFRESH_TOKEN,
        accessToken: accessToken.token,
      },
    });
    const mailOptions = {
      from: `DailyVotion <${SENDER}>`,
      to,
      subject: 'Your DailyVotion OTP Code',
      text: `Your OTP code is: ${otp}\nThis code will expire in 5 minutes.`,
    };
    const result = await transport.sendMail(mailOptions);
    return result;
  } catch (error) {
    console.error('Error sending OTP email:', error);
    throw error;
  }
}

module.exports = { sendOTPEmail };// dailyvotionbackend/mailer.js
const nodemailer = require('nodemailer');
const { google } = require('googleapis');

oAuth2Client.setCredentials({ refresh_token: REFRESH_TOKEN });

async function sendOTPEmail(to, otp) {
  try {
    const accessToken = await oAuth2Client.getAccessToken();
    const transport = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        type: 'OAuth2',
        user: process.env.GMAIL_SENDER, // your gmail address
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        refreshToken: REFRESH_TOKEN,
        accessToken: accessToken.token,
      },
    });

    const mailOptions = {
      from: `DailyVotion <${process.env.GMAIL_SENDER}>`,
      to,
      subject: 'Your DailyVotion OTP Code',
      text: `Your OTP code is: ${otp}\nThis code will expire in 5 minutes.`,
    };

    const result = await transport.sendMail(mailOptions);
    return result;
  } catch (error) {
    console.error('Error sending OTP email:', error);
    throw error;
  }
}

module.exports = { sendOTPEmail };