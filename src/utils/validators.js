import { z } from 'zod';

export const registerSchema = z.object({
  email: z.string().email('Please provide a valid email address'),
  password: z
    .string()
    .min(8, 'Password must be at least 8 characters')
    .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')  // ✅ Fixed
    .regex(/[a-z]/, 'Password must contain at least one lowercase letter')  // ✅ Fixed
    .regex(/[0-9]/, 'Password must contain at least one number'),           // ✅ Fixed
  name: z
    .string()
    .min(2, 'Name must be at least 2 characters')
    .max(50, 'Name cannot exceed 50 characters')
});

export const loginSchema = z.object({
  email: z.string().email('Please provide a valid email address'),
  password: z.string().min(1, 'Password is required')
});

export const forgotPasswordSchema = z.object({
  email: z.string().email('Please provide a valid email address')
});

export const resetPasswordSchema = z.object({
  token: z.string().min(1, 'Token is required'),
  newPassword: z
    .string()
    .min(8, 'Password must be at least 8 characters')
    .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')  // ✅ Fixed
    .regex(/[a-z]/, 'Password must contain at least one lowercase letter')  // ✅ Fixed
    .regex(/[0-9]/, 'Password must contain at least one number')            // ✅ Fixed
});

// Middleware to validate request body
export const validate = (schema) => {
  return (req, res, next) => {
    try {
      schema.parse(req.body);
      next();
    } catch (error) {
      return res.status(400).json({
        error: 'Validation failed',
        details: error.errors.map((e) => ({
          field: e.path.join('.'),
          message: e.message
        }))
      });
    }
  };
};