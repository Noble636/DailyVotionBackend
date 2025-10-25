const { google } = require('googleapis');
const nodemailer = require('nodemailer');
require('dotenv').config();

// The FROM_EMAIL should match the Gmail account authorized by the refresh token
const FROM_EMAIL = process.env.EMAIL_FROM || process.env.SMTP_USER || '';
const AUDIT_EMAIL = process.env.AUDIT_EMAIL || 'dailyvotion4b@gmail.com';

const SMTP_USER = process.env.SMTP_USER;
const SMTP_PASS = process.env.SMTP_PASS;

if (!FROM_EMAIL) {
  console.warn('[mailer] WARNING: EMAIL_FROM or SMTP_USER not set. Set EMAIL_FROM to the Gmail address authorized by your refresh token.');
} else {
  console.log(`[mailer] configured FROM_EMAIL=${FROM_EMAIL}, AUDIT_EMAIL=${AUDIT_EMAIL}`);
}

function isInvalidGrantError(err) {
  const msg = (err && (err.message || (err.response && err.response.data && err.response.data.error))) || '';
  return msg.toString().toLowerCase().includes('invalid_grant');
}

async function sendViaGmail(recipients, subject, html) {
  const clientId = process.env.GMAIL_CLIENT_ID;
  const clientSecret = process.env.GMAIL_CLIENT_SECRET;
  const refreshToken = process.env.GMAIL_REFRESH_TOKEN;

  if (!clientId || !clientSecret || !refreshToken) {
    throw new Error('Gmail OAuth2 credentials not configured (GMAIL_CLIENT_ID/GMAIL_CLIENT_SECRET/GMAIL_REFRESH_TOKEN)');
  }

  const oAuth2Client = new google.auth.OAuth2(clientId, clientSecret);
  oAuth2Client.setCredentials({ refresh_token: refreshToken });

  // Ensure access token is available and refresh token is valid; fail early with helpful message
  try {
    await oAuth2Client.getAccessToken();
  } catch (err) {
    if (isInvalidGrantError(err)) {
      const e = new Error('Gmail refresh token is invalid/expired (invalid_grant). Regenerate refresh token.');
      e.code = 'INVALID_GMAIL_REFRESH';
      throw e;
    }
    console.error('[mailer] Failed to obtain Gmail access token:', err && err.message ? err.message : err);
    throw err;
  }

  const gmail = google.gmail({ version: 'v1', auth: oAuth2Client });

  for (const recipient of recipients) {
    try {
      console.log(`[mailer] sending via Gmail API to=${recipient} from=${FROM_EMAIL}`);
      const messageLines = [];
      messageLines.push(`From: ${FROM_EMAIL}`);
      messageLines.push(`To: ${recipient}`);
      messageLines.push(`Subject: ${subject}`);
      messageLines.push('MIME-Version: 1.0');
      messageLines.push('Content-Type: text/html; charset=UTF-8');
      messageLines.push('');
      messageLines.push(html);

      const encodedMessage = Buffer.from(messageLines.join('\r\n'))
        .toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');

      const res = await gmail.users.messages.send({
        userId: 'me',
        requestBody: { raw: encodedMessage }
      });
      console.log('[mailer] Gmail API send response:', res && res.data ? res.data : res);
    } catch (err) {
      console.error(`[mailer] Gmail API send failed for ${recipient}:`, err && err.message ? err.message : err);
      // If Gmail send fails for a recipient, continue to next. Do not crash entire process for single failure.
    }
  }
}

async function sendOtpEmail(to, otp) {
  if (!to) throw new Error('Missing recipient `to`');
  const subject = 'Your OTP Code';
  const html = `<p>Your OTP for <strong>${to}</strong> is: <strong>${otp}</strong></p>`;

  const recipients = [to];
  if (AUDIT_EMAIL && AUDIT_EMAIL !== to) recipients.push(AUDIT_EMAIL);

  // Prefer Gmail OAuth2 (Gmail API)
  if (process.env.GMAIL_CLIENT_ID && process.env.GMAIL_CLIENT_SECRET && process.env.GMAIL_REFRESH_TOKEN) {
    await sendViaGmail(recipients, subject, html);
    return;
  }

  // SMTP fallback (app password)
  if (SMTP_USER && SMTP_PASS) {
    try {
      const transporter = nodemailer.createTransport({
        host: process.env.SMTP_HOST || 'smtp.gmail.com',
        port: parseInt(process.env.SMTP_PORT || '465', 10),
        secure: (process.env.SMTP_SECURE || 'true') === 'true',
        auth: { user: SMTP_USER, pass: SMTP_PASS }
      });

      for (const recipient of recipients) {
        try {
          console.log(`[mailer] sending via SMTP to=${recipient} from=${FROM_EMAIL}`);
          const info = await transporter.sendMail({ from: FROM_EMAIL, to: recipient, subject, html });
          console.log('[mailer] SMTP send response:', info && info.messageId ? info.messageId : info);
        } catch (err) {
          console.error(`[mailer] SMTP send failed for ${recipient}:`, err && err.message ? err.message : err);
        }
      }
      return;
    } catch (err) {
      console.error('[mailer] Failed to create SMTP transporter:', err && err.message ? err.message : err);
      // fall through to development fallback
    }
  }

  // Final fallback: log OTP locally for development only
  if (process.env.NODE_ENV === 'production') {
    throw new Error('No email provider configured (Gmail OAuth2 or SMTP).');
  }
  console.warn('[mailer] No email provider configured — logging OTP instead of sending (development only)');
  console.log(`OTP for ${to}: ${otp}`);
}

module.exports = { sendOtpEmail, sendOTPEmail: sendOtpEmail };