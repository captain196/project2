const SibApiV3Sdk = require("sib-api-v3-sdk");

let apiInstance = null;

function getBrevoApi() {
  if (!apiInstance) {
    const client = SibApiV3Sdk.ApiClient.instance;
    client.authentications["api-key"].apiKey = process.env.BREVO_API_KEY;
    apiInstance = new SibApiV3Sdk.TransactionalEmailsApi();
  }
  return apiInstance;
}

/**
 * Send OTP email via Brevo API (HTTPS, not SMTP — works on all cloud hosts).
 * Falls back to nodemailer SMTP only if Brevo fails.
 */
async function sendOtpEmail(toEmail, toName, otpCode) {
  const htmlContent = `
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
  `;

  // ── Primary: Brevo API (HTTPS) ──
  try {
    const sendSmtpEmail = new SibApiV3Sdk.SendSmtpEmail();
    sendSmtpEmail.sender = { name: "GraderIQ", email: process.env.EMAIL_USER || "graderiq@gmail.com" };
    sendSmtpEmail.to = [{ email: toEmail, name: toName || "User" }];
    sendSmtpEmail.subject = `Your Password Reset OTP: ${otpCode}`;
    sendSmtpEmail.htmlContent = htmlContent;

    const result = await getBrevoApi().sendTransacEmail(sendSmtpEmail);
    console.log("OTP email sent via Brevo:", result.messageId || "ok");
    return true;
  } catch (err) {
    console.error("Brevo email error:", err.message || err);
  }

  // ── Fallback: nodemailer SMTP with hard timeout ──
  try {
    const nodemailer = require("nodemailer");
    const transport = nodemailer.createTransport({
      host: "smtp.gmail.com",
      port: 587,
      secure: false,
      auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
      connectionTimeout: 8000,
      greetingTimeout: 8000,
      socketTimeout: 8000,
    });

    const info = await Promise.race([
      transport.sendMail({
        from: `"GraderIQ" <${process.env.EMAIL_USER}>`,
        to: toEmail,
        subject: `Your Password Reset OTP: ${otpCode}`,
        html: htmlContent,
      }),
      new Promise((_, rej) => setTimeout(() => rej(new Error("SMTP timeout")), 10000)),
    ]);
    console.log("OTP email sent via SMTP fallback:", info.messageId);
    return true;
  } catch (fallbackErr) {
    console.error("SMTP fallback also failed:", fallbackErr.message);
    return false;
  }
}

module.exports = { sendOtpEmail };
