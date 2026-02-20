import { verifyAccessToken } from '../services/tokenService.js';

export const authenticate = async (req, res, next) => {
  try {
    // 1. Get token from Authorization header
    const authHeader = req.headers.authorization;
    const token = authHeader?.split(' ')[1];  // ✅ Fixed - get the token part (index 1)
    
    // 2. Check if token exists
    if (!token) {
      return res.status(401).json({ error: 'Access denied. No token provided.' });
    }
    
    // 3. Verify token
    const decoded = verifyAccessToken(token);
    
    // 4. Add userId to req object
    req.userId = decoded.userId;
    
    // 5. Call next()
    next();
    
  } catch (error) {
    // Token is invalid or expired
    return res.status(401).json({ 
      error: 'Invalid or expired token' 
    });
  }
};