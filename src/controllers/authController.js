import bcrypt from 'bcrypt';
import { v4 as uuidv4 } from 'uuid';
import crypto from 'crypto';
import db from '../config/database.js';
import { users, auditLogs, refreshTokens } from '../../db/schema.js';
import { eq } from 'drizzle-orm';
import { 
  generateAccessToken, 
  generateRefreshToken,
  verifyRefreshToken,
  revokeRefreshToken
} from '../services/tokenService.js';
import { 
  sendVerificationEmail,
  sendPasswordResetEmail
} from '../services/emailService.js';

// Helper: Log audit event
const logAudit = async (userId, action, req, success, metadata = {}) => {
  await db.insert(auditLogs).values({
    userId,
    action,
    ipAddress: req.ip || req.connection.remoteAddress || 'unknown',  // ✅ Fixed
    userAgent: req.headers['user-agent'] || 'unknown',  // ✅ Fixed - get specific header
    success,
    metadata: JSON.stringify(metadata)
  });
};

// REGISTER
export const register = async (req, res) => {
  try {
    const { email, password, name } = req.body;

    // 1. Check if user already exists
    const [existingUser] = await db.select().from(users).where(eq(users.email, email));  // ✅ Fixed
    if (existingUser) {
      return res.status(409).json({ error: 'Email already registered' });
    }

    // 2. Hash password (12 rounds)
    const hashedPassword = await bcrypt.hash(password, 12);

    // 3. Generate email verification token & expiry (24 hours)
    const emailVerifyToken = crypto.randomBytes(32).toString('hex');
    const emailVerifyExpires = new Date(Date.now() + 24 * 60 * 60 * 1000);

    // 4. Create user in database
    const [newUser] = await db.insert(users).values({  // ✅ Fixed
      email,
      password: hashedPassword,
      name,
      emailVerifyToken,
      emailVerifyExpires,
      isEmailVerified: false
    }).returning();

    // 5. Send verification email
    await sendVerificationEmail(email, name, emailVerifyToken);

    // 6. Log audit event
    await logAudit(newUser.id, 'REGISTER', req, true);

    // 7. Return success
    return res.status(201).json({
      message: 'Registration successful. Please check your email to verify your account.',
      user: {
        id: newUser.id,
        name: newUser.name,
        email: newUser.email
      }
    });

  } catch (error) {
    console.error('Register error:', error);
    return res.status(500).json({ error: 'Server error' });
  }
};

// VERIFY EMAIL
export const verifyEmail = async (req, res) => {
  try {
    const { token } = req.query;

    // 1. Find user by emailVerifyToken
    const [user] = await db.select().from(users).where(eq(users.emailVerifyToken, token));  // ✅ Fixed
    if (!user) {
      return res.status(400).json({ error: 'Invalid verification token' });
    }

    // 2. Check if token expired
    if (new Date() > user.emailVerifyExpires) {
      return res.status(400).json({ error: 'Verification token has expired' });
    }

    // 3. Update user
    await db.update(users)
      .set({ 
        isEmailVerified: true, 
        emailVerifyToken: null, 
        emailVerifyExpires: null 
      })
      .where(eq(users.id, user.id));

    // 4. Return success
    return res.status(200).json({ message: 'Email verified successfully. You can now log in.' });

  } catch (error) {
    console.error('Verify email error:', error);
    return res.status(500).json({ error: 'Server error' });
  }
};

// LOGIN
export const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    // 1. Find user by email
    const [user] = await db.select().from(users).where(eq(users.email, email));  // ✅ Fixed
    
    // 2. If not found: return generic 401
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // 3. Check if email is verified
    if (!user.isEmailVerified) {
      return res.status(403).json({ error: 'Please verify your email first' });
    }

    // 4 & 5. Compare password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      await logAudit(user.id, 'LOGIN_FAILED', req, false);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // 6. Generate access token
    const accessToken = generateAccessToken(user.id);

    // 7. Generate refresh token
    const refreshToken = await generateRefreshToken(user.id);

    // 8. Log audit
    await logAudit(user.id, 'LOGIN', req, true);

    // 9. Return tokens + user data
    return res.status(200).json({
      accessToken,
      refreshToken,
      user: {
        id: user.id,
        name: user.name,
        email: user.email
      }
    });

  } catch (error) {
    console.error('Login error:', error);
    return res.status(500).json({ error: 'Server error' });
  }
};

// REFRESH TOKEN
export const refresh = async (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(400).json({ error: 'Refresh token is required' });
    }

    const validTokenRecord = await verifyRefreshToken(refreshToken);
    const newAccessToken = generateAccessToken(validTokenRecord.userId);

    return res.status(200).json({ accessToken: newAccessToken });

  } catch (error) {
    console.error('Refresh error:', error.message);
    return res.status(401).json({ error: 'Invalid or expired refresh token' });
  }
};

// LOGOUT
export const logout = async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) {
      return res.status(400).json({ error: 'Refresh token is required' });
    }

    const [tokenRecord] = await db.select().from(refreshTokens).where(eq(refreshTokens.token, refreshToken));  // ✅ Fixed

    if (tokenRecord) {
      await revokeRefreshToken(refreshToken);
      await logAudit(tokenRecord.userId, 'LOGOUT', req, true);
    }

    return res.status(200).json({ message: 'Logged out successfully' });

  } catch (error) {
    console.error('Logout error:', error);
    return res.status(500).json({ error: 'Server error' });
  }
};

// FORGOT PASSWORD
export const forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;

    const [user] = await db.select().from(users).where(eq(users.email, email));  // ✅ Fixed

    if (user) {
      const resetToken = crypto.randomBytes(32).toString('hex');
      const resetExpires = new Date(Date.now() + 60 * 60 * 1000); 

      await db.update(users)
        .set({ passwordResetToken: resetToken, passwordResetExpires: resetExpires })
        .where(eq(users.id, user.id));

      await sendPasswordResetEmail(user.email, user.name, resetToken);
      await logAudit(user.id, 'FORGOT_PASSWORD_REQUEST', req, true);
    }

    return res.status(200).json({ message: 'If that email exists in our system, a password reset link has been sent.' });

  } catch (error) {
    console.error('Forgot password error:', error);
    return res.status(500).json({ error: 'Server error' });
  }
};

// RESET PASSWORD
export const resetPassword = async (req, res) => {
  try {
    const { token, newPassword } = req.body;  // ✅ Fixed - match validator

    const [user] = await db.select().from(users).where(eq(users.passwordResetToken, token));  // ✅ Fixed
    if (!user) {
      return res.status(400).json({ error: 'Invalid reset token' });
    }

    if (new Date() > user.passwordResetExpires) {
      return res.status(400).json({ error: 'Reset token has expired' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 12);  // ✅ Fixed

    await db.update(users)
      .set({ 
        password: hashedPassword, 
        passwordResetToken: null, 
        passwordResetExpires: null 
      })
      .where(eq(users.id, user.id));

    await db.update(refreshTokens)
      .set({ isRevoked: true })
      .where(eq(refreshTokens.userId, user.id));

    await logAudit(user.id, 'PASSWORD_RESET', req, true);

    return res.status(200).json({ message: 'Password has been reset successfully. Please log in.' });

  } catch (error) {
    console.error('Reset password error:', error);
    return res.status(500).json({ error: 'Server error' });
  }
};

// GET CURRENT USER
export const getMe = async (req, res) => {
  try {
    const [user] = await db.select().from(users).where(eq(users.id, req.userId));  // ✅ Fixed

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    return res.status(200).json({
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        isEmailVerified: user.isEmailVerified
      }
    });

  } catch (error) {
    console.error('GetMe error:', error);
    return res.status(500).json({ error: 'Server error' });
  }
};