DailyVotion backend — Mailer & OTP setup

This file explains how to configure and test the OTP email sending (Gmail OAuth2 or SMTP fallback).

Required environment variables
- Preferred (Gmail API via OAuth2):
  - GMAIL_CLIENT_ID
  - GMAIL_CLIENT_SECRET
  - GMAIL_REFRESH_TOKEN  <-- obtain using `get_refresh_token.js`
  - EMAIL_FROM           <-- Gmail address that matches the refresh token
  - AUDIT_EMAIL (optional)

- SMTP fallback (app password):
  - SMTP_USER
  - SMTP_PASS
  - (optional) SMTP_HOST, SMTP_PORT, SMTP_SECURE

- Other useful env vars:
  - NODE_ENV=development|production
  - DB_* variables for your database

How the mailer works
- If GMAIL_CLIENT_ID/GMAIL_CLIENT_SECRET/GMAIL_REFRESH_TOKEN are present, the mailer uses Gmail REST API (gmail.users.messages.send).
- Otherwise, if SMTP_USER and SMTP_PASS are present, it uses SMTP via nodemailer.
- Otherwise, if NODE_ENV !== 'production', it prints the OTP to the logs (for development). In production it will error.

Generate a refresh token (recommended)
1. Ensure your Google Cloud OAuth client is set up with the redirect URI: http://localhost:3000/oauth2callback
2. Add GMAIL_CLIENT_ID and GMAIL_CLIENT_SECRET to your local .env or your shell environment.
3. Run in the backend folder:

```powershell
cd 'c:\Users\nikko\Desktop\Capstone\dailyvotionbackend'
node get_refresh_token.js
```

4. The script will open a browser window for consent and print the returned tokens in the terminal. Copy the refresh_token into your .env (GMAIL_REFRESH_TOKEN).

Test sending an OTP locally
1. Add the env vars to `dailyvotionbackend/.env` (or set them in your shell). Example `.env`:

```
GMAIL_CLIENT_ID=your_client_id
GMAIL_CLIENT_SECRET=your_client_secret
GMAIL_REFRESH_TOKEN=the_refresh_token
EMAIL_FROM=youremail@gmail.com
AUDIT_EMAIL=optional@you.com
NODE_ENV=development
TEST_TO=recipient@example.com
TEST_OTP=123456
```

2. Run the quick test harness (npm script):

```powershell
cd 'c:\Users\nikko\Desktop\Capstone\dailyvotionbackend'
npm run test-mailer
```

3. Watch the terminal logs. If Gmail OAuth is configured and valid you should see Gmail API send response logs. If the refresh token is invalid you'll see an explicit error with code INVALID_GMAIL_REFRESH.

Deploying to Render
- Add the same env vars in Render's environment configuration. Keep `EMAIL_FROM` exactly the Gmail account that authorized the refresh token. Save and redeploy.
- Check Render logs after testing to see mailer logs and any errors.

If you see INVALID_GMAIL_REFRESH in logs
- Regenerate the refresh token using `get_refresh_token.js` and update Render env var `GMAIL_REFRESH_TOKEN`.

If you want me to automate any of these steps (e.g., regenerate token, add env var templates, or change the frontend UI), tell me which and I'll update the repo accordingly.
