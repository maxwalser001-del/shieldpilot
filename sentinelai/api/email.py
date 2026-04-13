"""Email service for password reset and notifications."""

from __future__ import annotations

import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional

_logger = logging.getLogger(__name__)

from sentinelai.core.config import AuthConfig


class EmailService:
    """Send emails via SMTP for password reset and notifications."""

    def __init__(self, config: AuthConfig):
        self.config = config

    def is_configured(self) -> bool:
        """Check if SMTP is properly configured."""
        return bool(self.config.smtp_host and self.config.smtp_user)

    def send_password_reset(
        self,
        to_email: str,
        reset_token: str,
        username: Optional[str] = None,
    ) -> bool:
        """Send password reset email.

        Args:
            to_email: Recipient email address.
            reset_token: The password reset token (not hashed).
            username: Optional username for personalization.

        Returns:
            True if email was sent successfully, False otherwise.
        """
        if not self.is_configured():
            # SMTP not configured - log and return False
            _logger.warning("SMTP not configured. Password reset requested for %s (token not logged for security)", to_email)
            return False

        reset_url = f"{self.config.password_reset_url}{reset_token}"
        display_name = username or to_email.split("@")[0]

        subject = "ShieldPilot - Password Reset Request"

        text_body = f"""
Hello {display_name},

You requested a password reset for your ShieldPilot account.

Click the link below to reset your password:
{reset_url}

This link expires in 1 hour. If you didn't request this, please ignore this email.

Best regards,
The ShieldPilot Team
        """.strip()

        html_body = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .button {{
            display: inline-block;
            padding: 12px 24px;
            background-color: #10b981;
            color: white;
            text-decoration: none;
            border-radius: 6px;
            font-weight: 600;
        }}
        .footer {{ margin-top: 30px; color: #666; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <h2>Password Reset Request</h2>
        <p>Hello {display_name},</p>
        <p>You requested a password reset for your ShieldPilot account.</p>
        <p>
            <a href="{reset_url}" class="button">Reset Password</a>
        </p>
        <p>Or copy this link: <code>{reset_url}</code></p>
        <p><strong>This link expires in 1 hour.</strong></p>
        <p>If you didn't request this password reset, please ignore this email.</p>
        <div class="footer">
            <p>Best regards,<br>The ShieldPilot Team</p>
        </div>
    </div>
</body>
</html>
        """.strip()

        return self._send_email(to_email, subject, text_body, html_body)

    def send_email_verification(
        self,
        to_email: str,
        verification_token: str,
        username: Optional[str] = None,
        base_url: str = "http://localhost:8420",
    ) -> bool:
        """Send email verification link.

        Args:
            to_email: Recipient email address.
            verification_token: The verification token (not hashed).
            username: Optional username for personalization.
            base_url: Base URL of the ShieldPilot instance.

        Returns:
            True if email was sent successfully, False otherwise.
        """
        if not self.is_configured():
            _logger.warning("SMTP not configured. Email verification requested for %s (token not logged for security)", to_email)
            return False

        verify_url = f"{base_url}/api/auth/verify-email?token={verification_token}"
        display_name = username or to_email.split("@")[0]

        subject = "ShieldPilot - Verify Your Email"

        text_body = f"""
Hello {display_name},

Welcome to ShieldPilot! Please verify your email address by clicking the link below:

{verify_url}

This link expires in 24 hours. If you didn't create this account, please ignore this email.

Best regards,
The ShieldPilot Team
        """.strip()

        html_body = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .button {{
            display: inline-block;
            padding: 12px 24px;
            background-color: #39D2C0;
            color: #0D1117;
            text-decoration: none;
            border-radius: 6px;
            font-weight: 600;
        }}
        .footer {{ margin-top: 30px; color: #666; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <h2>Verify Your Email</h2>
        <p>Hello {display_name},</p>
        <p>Welcome to ShieldPilot! Please verify your email address to get full access to all features.</p>
        <p>
            <a href="{verify_url}" class="button">Verify Email</a>
        </p>
        <p>Or copy this link: <code>{verify_url}</code></p>
        <p><strong>This link expires in 24 hours.</strong></p>
        <p>If you didn't create this account, please ignore this email.</p>
        <div class="footer">
            <p>Best regards,<br>The ShieldPilot Team</p>
        </div>
    </div>
</body>
</html>
        """.strip()

        return self._send_email(to_email, subject, text_body, html_body)

    def send_account_deletion_confirmation(
        self,
        to_email: str,
        username: Optional[str] = None,
    ) -> bool:
        """Send account deletion confirmation email.

        Args:
            to_email: Email of the deleted account.
            username: Optional username for personalization.

        Returns:
            True if email was sent successfully, False otherwise.
        """
        if not self.is_configured():
            return False

        display_name = username or to_email.split("@")[0]

        subject = "ShieldPilot - Account Deleted"

        text_body = f"""
Hello {display_name},

Your ShieldPilot account has been permanently deleted as requested.

What was deleted:
- Your account profile and credentials
- Email verification and password reset tokens
- Usage records

What was anonymized (to preserve audit chain integrity):
- Command logs (command text replaced with [DELETED])
- Security incidents (details replaced with [DELETED])
- File change logs (paths replaced with [DELETED])
- Network access logs (destinations replaced with [DELETED])
- Scan results (sources replaced with [DELETED])

If you did not request this deletion, please contact us immediately.

Best regards,
The ShieldPilot Team
        """.strip()

        html_body = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f6f8fa; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; background: #ffffff; border-radius: 8px; }}
        h2 {{ color: #0D1117; }}
        .data-list {{ background: #f6f8fa; border-radius: 6px; padding: 16px 20px; margin: 16px 0; }}
        .data-list h3 {{ margin: 0 0 8px 0; font-size: 14px; color: #0D1117; }}
        .data-list ul {{ margin: 0; padding-left: 20px; color: #57606a; font-size: 13px; }}
        .data-list li {{ margin-bottom: 4px; }}
        .footer {{ margin-top: 30px; color: #666; font-size: 12px; border-top: 1px solid #e1e4e8; padding-top: 16px; }}
    </style>
</head>
<body>
    <div class="container">
        <h2>Account Deleted</h2>
        <p>Hello {display_name},</p>
        <p>Your ShieldPilot account has been permanently deleted as requested.</p>

        <div class="data-list">
            <h3>What was deleted:</h3>
            <ul>
                <li>Your account profile and credentials</li>
                <li>Email verification and password reset tokens</li>
                <li>Usage records</li>
            </ul>
        </div>

        <div class="data-list">
            <h3>What was anonymized (audit chain preserved):</h3>
            <ul>
                <li>Command logs (text replaced with [DELETED])</li>
                <li>Security incidents (details replaced with [DELETED])</li>
                <li>File change and network access logs</li>
                <li>Scan results</li>
            </ul>
        </div>

        <p>If you did not request this deletion, please contact us immediately.</p>

        <div class="footer">
            <p>Best regards,<br>The ShieldPilot Team</p>
        </div>
    </div>
</body>
</html>
        """.strip()

        return self._send_email(to_email, subject, text_body, html_body)

    def send_tier_upgrade_notification(
        self,
        to_email: str,
        new_tier: str,
        username: Optional[str] = None,
    ) -> bool:
        """Send tier upgrade notification email."""
        if not self.is_configured():
            return False

        display_name = username or to_email.split("@")[0]
        tier_display = "Pro+" if new_tier == "pro_plus" else new_tier.capitalize()

        subject = f"ShieldPilot — Welcome to {tier_display}!"

        text_body = f"""
Hello {display_name},

Your ShieldPilot subscription has been activated! You're now on the {tier_display} plan.

Your new features include:
- {'1,000' if new_tier == 'pro' else 'Unlimited'} commands per day
- {'100' if new_tier == 'pro' else 'Unlimited'} scans per day
{'- AI-powered threat analysis' + chr(10) if new_tier in ('pro_plus', 'enterprise') else ''}- Data export
- API access
{('- Multi-user support' + chr(10) + '- Priority support') if new_tier in ('pro_plus', 'enterprise') else ''}

Manage your subscription anytime in Settings or visit the Stripe Customer Portal.

Best regards,
The ShieldPilot Team
        """.strip()

        html_body = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f6f8fa; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; background: #ffffff; border-radius: 8px; }}
        h2 {{ color: #0D1117; }}
        .tier-badge {{ display: inline-block; padding: 4px 12px; background: rgba(57, 210, 192, 0.15); color: #39D2C0; border-radius: 12px; font-weight: 600; font-size: 14px; }}
        .feature-list {{ background: #f6f8fa; border-radius: 6px; padding: 16px 20px; margin: 16px 0; }}
        .feature-list ul {{ margin: 0; padding-left: 20px; color: #57606a; font-size: 13px; }}
        .feature-list li {{ margin-bottom: 4px; }}
        .footer {{ margin-top: 30px; color: #666; font-size: 12px; border-top: 1px solid #e1e4e8; padding-top: 16px; }}
    </style>
</head>
<body>
    <div class="container">
        <h2>Welcome to <span class="tier-badge">{tier_display}</span></h2>
        <p>Hello {display_name},</p>
        <p>Your ShieldPilot subscription is now active!</p>

        <div class="feature-list">
            <ul>
                <li>{'1,000' if new_tier == 'pro' else 'Unlimited'} commands per day</li>
                <li>{'100' if new_tier == 'pro' else 'Unlimited'} scans per day</li>
                {"<li>AI-powered threat analysis</li>" if new_tier in ("pro_plus", "enterprise") else ""}
                <li>Data export</li>
                <li>API access</li>
                {"<li>Multi-user support</li><li>Priority support</li>" if new_tier in ("pro_plus", "enterprise") else ""}
            </ul>
        </div>

        <p>Manage your subscription anytime in <strong>Settings</strong>.</p>

        <div class="footer">
            <p>Best regards,<br>The ShieldPilot Team</p>
        </div>
    </div>
</body>
</html>
        """.strip()

        return self._send_email(to_email, subject, text_body, html_body)

    def send_tier_downgrade_notification(
        self,
        to_email: str,
        old_tier: str,
        reason: str = "canceled",
        username: Optional[str] = None,
    ) -> bool:
        """Send tier downgrade notification email."""
        if not self.is_configured():
            return False

        display_name = username or to_email.split("@")[0]
        old_display = old_tier.capitalize()

        if reason == "canceled":
            reason_text = "Your subscription has been canceled."
        elif reason == "payment_failed":
            reason_text = "Your subscription was canceled due to a payment issue."
        else:
            reason_text = "Your subscription status has changed."

        subject = "ShieldPilot — Subscription Update"

        text_body = f"""
Hello {display_name},

{reason_text}

Your account has been reverted to the Free plan. Here's what changed:
- Command limit: 50 per day
- Scan limit: 10 per day
- History retention: 1 day
- LLM analysis: Disabled
- Data export: Disabled
- API access: Disabled

You can resubscribe anytime at the Pricing page.

Best regards,
The ShieldPilot Team
        """.strip()

        html_body = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f6f8fa; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; background: #ffffff; border-radius: 8px; }}
        h2 {{ color: #0D1117; }}
        .info-box {{ background: #f6f8fa; border-radius: 6px; padding: 16px 20px; margin: 16px 0; }}
        .info-box ul {{ margin: 0; padding-left: 20px; color: #57606a; font-size: 13px; }}
        .info-box li {{ margin-bottom: 4px; }}
        .footer {{ margin-top: 30px; color: #666; font-size: 12px; border-top: 1px solid #e1e4e8; padding-top: 16px; }}
    </style>
</head>
<body>
    <div class="container">
        <h2>Subscription Update</h2>
        <p>Hello {display_name},</p>
        <p>{reason_text}</p>
        <p>Your account has been reverted to the <strong>Free</strong> plan.</p>

        <div class="info-box">
            <ul>
                <li>Command limit: 50 per day</li>
                <li>Scan limit: 10 per day</li>
                <li>History retention: 1 day</li>
                <li>LLM analysis: Disabled</li>
                <li>Data export: Disabled</li>
            </ul>
        </div>

        <p>You can resubscribe anytime from the <strong>Pricing</strong> page.</p>

        <div class="footer">
            <p>Best regards,<br>The ShieldPilot Team</p>
        </div>
    </div>
</body>
</html>
        """.strip()

        return self._send_email(to_email, subject, text_body, html_body)

    def send_payment_failed_notification(
        self,
        to_email: str,
        tier: str,
        username: Optional[str] = None,
    ) -> bool:
        """Send payment failure notification email."""
        if not self.is_configured():
            return False

        display_name = username or to_email.split("@")[0]
        tier_display = tier.capitalize()

        subject = "ShieldPilot — Payment Issue"

        text_body = f"""
Hello {display_name},

We were unable to process your latest payment for the ShieldPilot {tier_display} plan.

Don't worry — your {tier_display} features remain active while we retry. Please update your payment method to avoid any interruption:

1. Log in to ShieldPilot
2. Go to Settings > Subscription > Manage Subscription
3. Update your payment method

We'll automatically retry the payment. If the issue persists, your subscription may be canceled.

Best regards,
The ShieldPilot Team
        """.strip()

        html_body = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f6f8fa; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; background: #ffffff; border-radius: 8px; }}
        h2 {{ color: #0D1117; }}
        .warning-box {{ background: rgba(245, 158, 11, 0.08); border-left: 4px solid #f59e0b; border-radius: 6px; padding: 16px 20px; margin: 16px 0; }}
        .steps {{ margin: 16px 0; }}
        .steps ol {{ padding-left: 20px; color: #57606a; font-size: 13px; }}
        .steps li {{ margin-bottom: 8px; }}
        .footer {{ margin-top: 30px; color: #666; font-size: 12px; border-top: 1px solid #e1e4e8; padding-top: 16px; }}
    </style>
</head>
<body>
    <div class="container">
        <h2>Payment Issue</h2>
        <p>Hello {display_name},</p>

        <div class="warning-box">
            <p>We were unable to process your latest payment for the <strong>{tier_display}</strong> plan.</p>
            <p>Your {tier_display} features remain active while we retry the payment.</p>
        </div>

        <div class="steps">
            <p>Please update your payment method:</p>
            <ol>
                <li>Log in to ShieldPilot</li>
                <li>Go to <strong>Settings → Subscription → Manage Subscription</strong></li>
                <li>Update your payment method</li>
            </ol>
        </div>

        <p>If the issue persists, your subscription may be canceled.</p>

        <div class="footer">
            <p>Best regards,<br>The ShieldPilot Team</p>
        </div>
    </div>
</body>
</html>
        """.strip()

        return self._send_email(to_email, subject, text_body, html_body)

    def _send_email(
        self,
        to_email: str,
        subject: str,
        text_body: str,
        html_body: str,
    ) -> bool:
        """Send an email via SMTP.

        Returns:
            True if successful, False otherwise.
        """
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = self.config.smtp_from_email
            msg["To"] = to_email

            msg.attach(MIMEText(text_body, "plain"))
            msg.attach(MIMEText(html_body, "html"))

            with smtplib.SMTP(self.config.smtp_host, self.config.smtp_port) as server:
                server.starttls()
                if self.config.smtp_user and self.config.smtp_password:
                    server.login(self.config.smtp_user, self.config.smtp_password)
                server.sendmail(self.config.smtp_from_email, to_email, msg.as_string())

            return True

        except Exception as e:
            _logger.error("Failed to send email to %s: %s", to_email, e)
            return False
