import nodemailer from "nodemailer";

const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: process.env.EMAIL_PORT,
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,  
    }
});

// Verify connection on startup
transporter.verify((error, success) => {
    if (error) {
        console.error('❌ Email service error:', error);
    } else {
        console.log('✅ Email service ready');
    }
});

export const sendVerificationEmail = async (email, name, token) => {
    try {
        const verifyUrl = `${process.env.APP_URL}/api/auth/verify-email?token=${token}`; 

        await transporter.sendMail({
            from: process.env.EMAIL_FROM,
            to: email,
            subject: "Verify your email",
            html: `
                <h1>Welcome, ${name}!</h1>
                <p>Please verify your email address by clicking the link below:</p>
                <a href="${verifyUrl}">Verify My Email</a>
                <p>If you did not create an account, please ignore this email.</p>
                <p style="color: #666; font-size: 12px;">This link expires in 24 hours.</p>
            `,
        });
        
        console.log(`✅ Verification email sent to ${email}`);
    } catch (error) {
        console.error('❌ Failed to send verification email:', error.message);
        throw new Error('Failed to send verification email');
    }
};

export const sendPasswordResetEmail = async (email, name, token) => {
    try {
        const resetUrl = `${process.env.FRONTEND_URL}/reset-password?token=${token}`;

        await transporter.sendMail({
            from: process.env.EMAIL_FROM,
            to: email,
            subject: "Reset your Password",
            html: `
                <h1>Hello, ${name}</h1>
                <p>We received a request to reset your password.</p>
                <a href="${resetUrl}">Reset Password</a>
                <p>This link expires in 1 hour.</p>
                <p style="color: #666;">If you did not request this, please ignore this email.</p>
            `,
        });
        
        console.log(`✅ Password reset email sent to ${email}`);
    } catch (error) {
        console.error('❌ Failed to send password reset email:', error.message);
        throw new Error('Failed to send password reset email');
    }
};