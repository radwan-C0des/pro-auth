import express from 'express';
const router = express.Router();

import { 
  register, verifyEmail, login, 
  refresh, logout, forgotPassword, 
  resetPassword, getMe 
} from '../controllers/authController.js';

import { authenticate } from '../middleware/authMiddleware.js';
import { validate, registerSchema, loginSchema, forgotPasswordSchema, resetPasswordSchema } from '../utils/validators.js';
import { authLimiter } from '../middleware/rateLimitMiddleware.js';

// Public routes
router.post('/register',authLimiter, validate(registerSchema), register);
router.get('/verify-email', verifyEmail);
router.post('/login',authLimiter, validate(loginSchema), login);
router.post('/refresh', refresh);
router.post('/forgot-password', validate(forgotPasswordSchema), forgotPassword);
router.post('/reset-password', validate(resetPasswordSchema), resetPassword);

// Protected routes
router.post('/logout', authenticate, logout);
router.get('/me', authenticate, getMe);

export default router;