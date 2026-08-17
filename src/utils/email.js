/**
 * OTP Email.
 * Primary transport: Gmail SMTP via nodemailer (EMAIL_USER / EMAIL_PASS).
 * Fallback transport: Brevo HTTP API (BREVO_API_KEY) when Gmail is not
 * configured or its send fails. Returns true if any transport delivered.
 */
const nodemailer = require("nodemailer");

let _gmailTx = null;
function gmailTransport() {
  if (_gmailTx) return _gmailTx;
  if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) return null;
  _gmailTx = nodemailer.createTransport({
    service: "gmail",
    auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
  });
  return _gmailTx;
}

function otpHtml(toName, otpCode) {
  return `
    <div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto;padding:24px;">
      <div style="text-align:center;padding:20px 0;border-bottom:2px solid #0f766e;">
        <h2 style="margin:0;color:#0f766e;font-size:22px;">ZenXii</h2>
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
        <p style="margin:0;color:#999;font-size:11px;">ZenXii School ERP</p>
      </div>
    </div>
  `;
}

async function sendViaGmail(toEmail, toName, otpCode) {
  const tx = gmailTransport();
  if (!tx) return false;
  try {
    const info = await tx.sendMail({
      from: `"ZenXii" <${process.env.EMAIL_USER}>`,
      to: toEmail,
      subject: `Your Password Reset OTP: ${otpCode}`,
      html: otpHtml(toName, otpCode),
    });
    console.log("OTP email sent via Gmail SMTP:", info.messageId || "ok");
    return true;
  } catch (err) {
    console.error("Gmail SMTP error:", err.message);
    return false;
  }
}

async function sendViaBrevo(toEmail, toName, otpCode) {
  if (!process.env.BREVO_API_KEY) return false;
  try {
    const response = await fetch("https://api.brevo.com/v3/smtp/email", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "api-key": process.env.BREVO_API_KEY,
      },
      body: JSON.stringify({
        sender: { name: "ZenXii", email: "yugant196@gmail.com" },
        to: [{ email: toEmail, name: toName || "User" }],
        subject: `Your Password Reset OTP: ${otpCode}`,
        htmlContent: otpHtml(toName, otpCode),
      }),
      signal: AbortSignal.timeout(10000),
    });
    if (response.ok) {
      const data = await response.json();
      console.log("OTP email sent via Brevo API:", data.messageId || "ok");
      return true;
    }
    console.error("Brevo API error:", response.status, await response.text());
    return false;
  } catch (err) {
    console.error("Brevo send error:", err.message);
    return false;
  }
}

async function sendOtpEmail(toEmail, toName, otpCode) {
  // Try Gmail first; fall back to Brevo if Gmail isn't configured or fails.
  if (await sendViaGmail(toEmail, toName, otpCode)) return true;
  return sendViaBrevo(toEmail, toName, otpCode);
}

module.exports = { sendOtpEmail };
