const { google } = require('googleapis');
const nodemailer = require('nodemailer');
require('dotenv').config();

const FROM_EMAIL = process.env.EMAIL_FROM || process.env.SMTP_USER || '';
const AUDIT_EMAIL = process.env.AUDIT_EMAIL || '';

const SMTP_USER = process.env.SMTP_USER;
const SMTP_PASS = process.env.SMTP_PASS;

if (!FROM_EMAIL) {
  console.warn('[mailer] WARNING: EMAIL_FROM / SMTP_USER not set. Set EMAIL_FROM to the Gmail address authorized by your refresh token.');
} else {
  console.log(`[mailer] FROM_EMAIL=${FROM_EMAIL}, AUDIT_EMAIL=${AUDIT_EMAIL || '(none)'}`);
}

function isInvalidGrantError(err) {
  // googleapis errors sometimes appear with err.errors or err.response.data
  const msg = (err && (err.message || (err.response && err.response.data && err.response.data.error))) || '';
  return msg.toString().toLowerCase().includes('invalid_grant');
}

async function sendViaGmailApi(recipients, subject, html) {
  const clientId = process.env.GMAIL_CLIENT_ID;
  const clientSecret = process.env.GMAIL_CLIENT_SECRET;
  const refreshToken = process.env.GMAIL_REFRESH_TOKEN;

  if (!clientId || !clientSecret || !refreshToken) {
    throw new Error('Gmail OAuth2 credentials not configured (CLIENT_ID/CLIENT_SECRET/REFRESH_TOKEN)');
  }

  const oAuth2Client = new google.auth.OAuth2(clientId, clientSecret);
  oAuth2Client.setCredentials({ refresh_token: refreshToken });

  // Optional: try to get a fresh access token to fail early on invalid_grant
  try {
    await oAuth2Client.getAccessToken();
  } catch (err) {
    if (isInvalidGrantError(err)) {
      const e = new Error('Gmail refresh token is invalid/expired (invalid_grant). Regenerate refresh token.');
      e.code = 'INVALID_GMAIL_REFRESH';
      throw e;
    }
    throw err;
  }

  const gmail = google.gmail({ version: 'v1', auth: oAuth2Client });

  for (const to of recipients) {
    const messageLines = [
      `From: ${FROM_EMAIL}`,
      `To: ${to}`,
      `Subject: ${subject}`,
      'MIME-Version: 1.0',
      'Content-Type: text/html; charset=UTF-8',
      '',
      html
    ];
    const raw = Buffer.from(messageLines.join('\r\n'))
      .toString('base64')
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

    await gmail.users.messages.send({
      userId: 'me',
      requestBody: { raw }
    });
  }
}

async function sendOtpEmail(to, otp) {
  if (!to) throw new Error('Missing recipient `to`');
  const subject = 'Your OTP Code';
  const html = `<p>Your OTP: <strong>${otp}</strong></p>`;

  const recipients = [to];
  if (AUDIT_EMAIL && AUDIT_EMAIL !== to) recipients.push(AUDIT_EMAIL);

  // Prefer Gmail API (OAuth2)
  if (process.env.GMAIL_CLIENT_ID && process.env.GMAIL_CLIENT_SECRET && process.env.GMAIL_REFRESH_TOKEN) {
    await sendViaGmailApi(recipients, subject, html);
    return;
  }

  // SMTP fallback (app password)
  if (SMTP_USER && SMTP_PASS) {
    const transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST || 'smtp.gmail.com',
      port: parseInt(process.env.SMTP_PORT || '465', 10),
      secure: (process.env.SMTP_SECURE || 'true') === 'true',
      auth: { user: SMTP_USER, pass: SMTP_PASS }
    });
    for (const recipient of recipients) {
      await transporter.sendMail({ from: FROM_EMAIL, to: recipient, subject, html });
    }
    return;
  }

  // Dev fallback: do not print OTP in prod
  if (process.env.NODE_ENV === 'production') {
    throw new Error('No email provider configured (Gmail OAuth2 or SMTP).');
  }
  console.warn('[mailer] No provider configured; logging OTP (development only)');
  console.log(`OTP for ${to}: ${otp}`);
}

module.exports = {
  sendOtpEmail,
  // export legacy name used by server.js if needed
  sendOTPEmail: sendOtpEmail
};