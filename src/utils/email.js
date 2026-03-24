/**
 * OTP Email — uses Brevo HTTP API (no SMTP, works on all cloud hosts).
 * Verified sender: yugant196@gmail.com (Brevo sender ID 1).
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

  try {
    const response = await fetch("https://api.brevo.com/v3/smtp/email", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "api-key": process.env.BREVO_API_KEY,
      },
      body: JSON.stringify({
        sender: { name: "GraderIQ", email: "yugant196@gmail.com" },
        to: [{ email: toEmail, name: toName || "User" }],
        subject: `Your Password Reset OTP: ${otpCode}`,
        htmlContent,
      }),
      signal: AbortSignal.timeout(10000),
    });

    if (response.ok) {
      const data = await response.json();
      console.log("OTP email sent via Brevo API:", data.messageId || "ok");
      return true;
    }

    const errText = await response.text();
    console.error("Brevo API error:", response.status, errText);
    return false;
  } catch (err) {
    console.error("Email send error:", err.message);
    return false;
  }
}

module.exports = { sendOtpEmail };
