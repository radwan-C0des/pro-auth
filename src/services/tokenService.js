import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from "uuid";
import db from "../config/database.js";
import { refreshTokens } from '../../db/schema.js';
import { eq } from "drizzle-orm";

// Generate access token (short-lived: 15 minutes)
export const generateAccessToken = (userId) => {
    return jwt.sign(
        { userId },
        process.env.JWT_ACCESS_SECRET,
        { expiresIn: process.env.JWT_ACCESS_EXPIRES }
    );
};

// Generate refresh token (long-lived: 7 days)
export const generateRefreshToken = async (userId) => {
    const token = uuidv4();
    
    // ✅ FIX: Calculate actual expiry date
    const daysMatch = process.env.JWT_REFRESH_EXPIRES.match(/(\d+)d/);
    const days = daysMatch ? parseInt(daysMatch[1]) : 7;
    
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + days);
    
    await db.insert(refreshTokens).values({
        token,
        userId,
        expiresAt
    });
    
    return token;
};

// Verify access token
export const verifyAccessToken = (token) => {
    try {
        return jwt.verify(token, process.env.JWT_ACCESS_SECRET);
    } catch (error) {
        throw new Error('Invalid or expired access token');
    }
};

// Verify refresh token
export const verifyRefreshToken = async (token) => {
    const [storedToken] = await db
        .select()
        .from(refreshTokens)
        .where(eq(refreshTokens.token, token));

    if (!storedToken) {
        throw new Error('Refresh token not found');
    }

    if (storedToken.isRevoked) {
        throw new Error('Refresh token has been revoked');
    }

    const now = new Date();
    if (now > storedToken.expiresAt) {
        throw new Error('Refresh token expired');
    }

    return storedToken;
};

// Revoke refresh token (on logout)
export const revokeRefreshToken = async (token) => {
    await db
        .update(refreshTokens)
        .set({ isRevoked: true })
        .where(eq(refreshTokens.token, token));
};

// ✅ NEW: Revoke all tokens for a user (used on password reset)
export const revokeAllUserTokens = async (userId) => {
    await db
        .update(refreshTokens)
        .set({ isRevoked: true })
        .where(eq(refreshTokens.userId, userId));
};