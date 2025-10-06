import nodemailer from 'nodemailer';

interface EmailOptions {
  to: string;
  subject: string;
  text?: string;
  html?: string;
}

interface VerificationEmailData {
  to: string;
  name: string;
  verificationUrl: string;
}

interface PasswordResetEmailData {
  to: string;
  name: string;
  resetUrl: string;
}

interface WelcomeEmailData {
  to: string;
  name: string;
  email: string;
  password: string;
  loginUrl: string;
}

class EmailService {
  private transporter: nodemailer.Transporter | null = null;
  private isConfigured = false;

  constructor() {
    this.initializeTransporter();
  }

  private initializeTransporter() {
    try {
      // Check if all required SMTP environment variables are present
      const requiredVars = ['EMAIL_SMTP_HOST', 'EMAIL_SMTP_PORT', 'EMAIL_SMTP_USER', 'EMAIL_SMTP_PASSWORD'];
      const missingVars = requiredVars.filter(varName => !process.env[varName]);
      
      if (missingVars.length > 0) {
        console.warn(`Email service not configured. Missing environment variables: ${missingVars.join(', ')}`);
        return;
      }

      this.transporter = nodemailer.createTransport({
        host: process.env.EMAIL_SMTP_HOST!,
        port: parseInt(process.env.EMAIL_SMTP_PORT!, 10),
        secure: process.env.EMAIL_SMTP_PORT === '465', // true for 465, false for 587
        auth: {
          user: process.env.EMAIL_SMTP_USER!,
          pass: process.env.EMAIL_SMTP_PASSWORD!,
        },
        tls: {
          // Don't fail on invalid certs for development
          rejectUnauthorized: process.env.NODE_ENV === 'production'
        }
      });

      this.isConfigured = true;
      console.log('Email service initialized successfully');
    } catch (error) {
      console.error('Failed to initialize email service:', error);
    }
  }

  async sendEmail(options: EmailOptions): Promise<boolean> {
    if (!this.isConfigured || !this.transporter) {
      console.warn('Email service not configured. Email not sent.');
      
      // In development, log the email content instead of sending
      if (process.env.NODE_ENV !== 'production') {
        console.log('EMAIL (DEV MODE):', {
          to: options.to,
          subject: options.subject,
          text: options.text,
          html: options.html
        });
      }
      return false;
    }

    try {
      const mailOptions = {
        from: `"Prasuti.AI IDM" <${process.env.EMAIL_SMTP_USER}>`,
        to: options.to,
        subject: options.subject,
        text: options.text,
        html: options.html,
      };

      const result = await this.transporter.sendMail(mailOptions);
      console.log(`Email sent successfully to ${options.to}`, { messageId: result.messageId });
      return true;
    } catch (error) {
      console.error(`Failed to send email to ${options.to}:`, error);
      return false;
    }
  }

  async sendVerificationEmail(data: VerificationEmailData): Promise<boolean> {
    const subject = 'Verify Your Email - Prasuti.AI IDM';
    
    const text = `
Hello ${data.name},

Welcome to Prasuti.AI IDM! Please verify your email address by clicking the link below:

${data.verificationUrl}

This link will expire in 24 hours for security reasons.

If you didn't create an account with us, please ignore this email.

Best regards,
The Prasuti.AI Team
    `.trim();

    const html = `
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Verify Your Email</title>
    <style>
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
        }
        .header {
            text-align: center;
            padding: 20px 0;
            border-bottom: 2px solid #f0f0f0;
            margin-bottom: 30px;
        }
        .logo {
            font-size: 24px;
            font-weight: bold;
            color: #2563eb;
        }
        .content {
            padding: 20px 0;
        }
        .button {
            display: inline-block;
            background: linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%);
            color: white !important;
            padding: 12px 30px;
            text-decoration: none;
            border-radius: 8px;
            font-weight: 600;
            margin: 20px 0;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }
        .footer {
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #f0f0f0;
            font-size: 14px;
            color: #666;
        }
        .security-note {
            background: #f8f9fa;
            border-left: 4px solid #ffc107;
            padding: 15px;
            margin: 20px 0;
            border-radius: 4px;
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="logo">🛡️ Prasuti.AI IDM</div>
    </div>
    
    <div class="content">
        <h1>Welcome to Prasuti.AI IDM!</h1>
        
        <p>Hello <strong>${data.name}</strong>,</p>
        
        <p>Thank you for creating an account with Prasuti.AI Identity Management. To complete your registration and secure your account, please verify your email address by clicking the button below:</p>
        
        <center>
            <a href="${data.verificationUrl}" class="button">Verify Email Address</a>
        </center>
        
        <p>Or copy and paste this link into your browser:</p>
        <p style="word-break: break-all; color: #2563eb;">${data.verificationUrl}</p>
        
        <div class="security-note">
            <strong>Security Notice:</strong> This verification link will expire in 24 hours for your security. If you didn't create an account with us, please ignore this email.
        </div>
        
        <p>Once verified, you'll have access to our secure identity management platform with enterprise-grade security features.</p>
    </div>
    
    <div class="footer">
        <p>Best regards,<br>The Prasuti.AI Team</p>
        <p><small>This is an automated message. Please do not reply to this email.</small></p>
    </div>
</body>
</html>
    `.trim();

    return this.sendEmail({
      to: data.to,
      subject,
      text,
      html
    });
  }

  async sendPasswordResetEmail(data: PasswordResetEmailData): Promise<boolean> {
    const subject = 'Reset Your Password - Prasuti.AI IDM';
    
    const text = `
Hello ${data.name},

We received a request to reset your password for your Prasuti.AI IDM account.

Click the link below to reset your password:

${data.resetUrl}

This link will expire in 1 hour for security reasons.

If you didn't request a password reset, please ignore this email. Your password will remain unchanged.

Best regards,
The Prasuti.AI Team
    `.trim();

    const html = `
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Reset Your Password</title>
    <style>
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
        }
        .header {
            text-align: center;
            padding: 20px 0;
            border-bottom: 2px solid #f0f0f0;
            margin-bottom: 30px;
        }
        .logo {
            font-size: 24px;
            font-weight: bold;
            color: #2563eb;
        }
        .content {
            padding: 20px 0;
        }
        .button {
            display: inline-block;
            background: linear-gradient(135deg, #dc2626 0%, #b91c1c 100%);
            color: white !important;
            padding: 12px 30px;
            text-decoration: none;
            border-radius: 8px;
            font-weight: 600;
            margin: 20px 0;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }
        .footer {
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #f0f0f0;
            font-size: 14px;
            color: #666;
        }
        .security-note {
            background: #fef2f2;
            border-left: 4px solid #dc2626;
            padding: 15px;
            margin: 20px 0;
            border-radius: 4px;
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="logo">🛡️ Prasuti.AI IDM</div>
    </div>
    
    <div class="content">
        <h1>Password Reset Request</h1>
        
        <p>Hello <strong>${data.name}</strong>,</p>
        
        <p>We received a request to reset your password for your Prasuti.AI IDM account. Click the button below to create a new password:</p>
        
        <center>
            <a href="${data.resetUrl}" class="button">Reset Password</a>
        </center>
        
        <p>Or copy and paste this link into your browser:</p>
        <p style="word-break: break-all; color: #dc2626;">${data.resetUrl}</p>
        
        <div class="security-note">
            <strong>Security Notice:</strong> This password reset link will expire in 1 hour. If you didn't request a password reset, please ignore this email and your password will remain unchanged.
        </div>
        
        <p>For your security, this link can only be used once. If you need to reset your password again, please make a new request.</p>
    </div>
    
    <div class="footer">
        <p>Best regards,<br>The Prasuti.AI Team</p>
        <p><small>This is an automated message. Please do not reply to this email.</small></p>
    </div>
</body>
</html>
    `.trim();

    return this.sendEmail({
      to: data.to,
      subject,
      text,
      html
    });
  }

  async sendWelcomeEmail(data: WelcomeEmailData): Promise<boolean> {
    const subject = 'Welcome to Prasuti.AI - Your Account Credentials';
    
    const text = `
Hello ${data.name},

Welcome to Prasuti.AI! Your account has been created successfully.

Your Login Credentials:
Email: ${data.email}
Password: ${data.password}

Login URL: ${data.loginUrl}

IMPORTANT: For security reasons, you will be required to change this password on your first login.

Please keep these credentials secure and do not share them with anyone.

Best regards,
The Prasuti.AI Team
    `.trim();

    const html = `
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Welcome to Prasuti.AI</title>
    <style>
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
        }
        .header {
            text-align: center;
            padding: 20px 0;
            border-bottom: 2px solid #f0f0f0;
            margin-bottom: 30px;
        }
        .logo {
            font-size: 24px;
            font-weight: bold;
            color: #2563eb;
        }
        .content {
            padding: 20px 0;
        }
        .credentials-box {
            background: #f8f9fa;
            border-left: 4px solid #2563eb;
            padding: 20px;
            margin: 20px 0;
            border-radius: 4px;
        }
        .credentials-box .credential-item {
            margin: 10px 0;
        }
        .credentials-box .credential-label {
            font-weight: 600;
            color: #666;
        }
        .credentials-box .credential-value {
            font-family: monospace;
            color: #2563eb;
            background: white;
            padding: 5px 10px;
            border-radius: 4px;
            display: inline-block;
            margin-top: 5px;
        }
        .button {
            display: inline-block;
            background: linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%);
            color: white !important;
            padding: 12px 30px;
            text-decoration: none;
            border-radius: 8px;
            font-weight: 600;
            margin: 20px 0;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }
        .footer {
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #f0f0f0;
            font-size: 14px;
            color: #666;
        }
        .security-note {
            background: #fef2f2;
            border-left: 4px solid #dc2626;
            padding: 15px;
            margin: 20px 0;
            border-radius: 4px;
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="logo">🛡️ Prasuti.AI</div>
    </div>
    
    <div class="content">
        <h1>Welcome to Prasuti.AI!</h1>
        
        <p>Hello <strong>${data.name}</strong>,</p>
        
        <p>Your account has been created successfully. Below are your login credentials:</p>
        
        <div class="credentials-box">
            <div class="credential-item">
                <div class="credential-label">Email Address:</div>
                <div class="credential-value">${data.email}</div>
            </div>
            <div class="credential-item">
                <div class="credential-label">Temporary Password:</div>
                <div class="credential-value">${data.password}</div>
            </div>
        </div>
        
        <center>
            <a href="${data.loginUrl}" class="button">Login to Your Account</a>
        </center>
        
        <p>Or copy and paste this link into your browser:</p>
        <p style="word-break: break-all; color: #2563eb;">${data.loginUrl}</p>
        
        <div class="security-note">
            <strong>🔒 Security Notice:</strong> For your security, you will be required to change this password on your first login. Please keep these credentials secure and do not share them with anyone.
        </div>
        
        <p>If you have any questions or need assistance, please don't hesitate to contact our support team.</p>
    </div>
    
    <div class="footer">
        <p>Best regards,<br>The Prasuti.AI Team</p>
        <p><small>This is an automated message. Please do not reply to this email.</small></p>
    </div>
</body>
</html>
    `.trim();

    return this.sendEmail({
      to: data.to,
      subject,
      text,
      html
    });
  }

  async testConnection(): Promise<boolean> {
    if (!this.isConfigured || !this.transporter) {
      console.warn('Email service not configured for connection test');
      return false;
    }

    try {
      await this.transporter.verify();
      console.log('Email service connection test successful');
      return true;
    } catch (error) {
      console.error('Email service connection test failed:', error);
      return false;
    }
  }
}

// Export singleton instance
export const emailService = new EmailService();
export default emailService;