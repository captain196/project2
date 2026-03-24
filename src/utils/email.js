const nodemailer = require("nodemailer");

let transporter = null;

function getTransporter() {
  if (!transporter) {
    // Use Brevo SMTP relay — works on Render (Gmail SMTP port 587 is blocked)
    transporter = nodemailer.createTransport({
      host: "smtp-relay.brevo.com",
      port: 587,
      secure: false,
      auth: {
        user: "a1a16f001@smtp-brevo.com",
        pass: process.env.BREVO_API_KEY,
      },
      connectionTimeout: 10000,
      greetingTimeout: 10000,
      socketTimeout: 10000,
    });
  }
  return transporter;
}

async function sendOtpEmail(toEmail, toName, otpCode) {
  const mailOptions = {
    from: `"GraderIQ" <yugant196@gmail.com>`,
    to: toEmail,
    subject: `Your Password Reset OTP: ${otpCode}`,
    html: `
      <div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto;padding:24px;">
        <div style="text-align:center;padding:20px 0;border-bottom:2px solid #0f766e;">
          <h2 style="margin:0;color:#0f766e;font-size:22px;">GraderIQ</h2>
          <p style="margin:4px 0 0;color:#666;font-size:12px;">Password Reset Request</p>
        </div>
        <div style="padding:24px 0;">
          <p style="margin:0 0 16px;color:#333;">Hi <strong>${toName || "Admin"}</strong>,</p>
          <p style="margin:0 0 20px;color:#333;">Use the following OTP to reset your password:</p>
          <div style="text-align:center;padding:16px;background:#f0f7f5;border-radius:10px;margin:0 0 20px;">
            <span style="font-size:32px;font-weight:700;letter-spacing:8px;color:#0f766e;">${otpCode}</span>
          </div>
          <p style="margin:0 0 8px;color:#666;font-size:13px;">This OTP expires in <strong>5 minutes</strong>.</p>
          <p style="margin:0;color:#666;font-size:13px;">If you didn't request this, ignore this email.</p>
        </div>
        <div style="padding:16px 0;border-top:1px solid #eee;text-align:center;">
          <p style="margin:0;color:#999;font-size:11px;">GraderIQ School ERP</p>
        </div>
      </div>
    `,
  };

  const sendWithTimeout = () =>
    Promise.race([
      getTransporter().sendMail(mailOptions),
      new Promise((_, rej) => setTimeout(() => rej(new Error("SMTP timeout")), 12000)),
    ]);

  try {
    const info = await sendWithTimeout();
    console.log("OTP email sent:", info.messageId);
    return true;
  } catch (err) {
    console.error("Email send error (attempt 1):", err.message);
    transporter = null;
    try {
      const info = await sendWithTimeout();
      console.log("OTP email sent (retry):", info.messageId);
      return true;
    } catch (retryErr) {
      console.error("Email send error (attempt 2):", retryErr.message);
      return false;
    }
  }
}

module.exports = { sendOtpEmail };
