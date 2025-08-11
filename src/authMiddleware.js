import jwt from 'jsonwebtoken';


export const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
  
    if (!token) {
      return res.status(401).json({ message: 'Access token required' });
    }
  
    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
      if (err) {
        return res.status(403).json({ message: 'Invalid token' });
      }
      
      // Add null checks here
      if (!decoded || !decoded.user) {
        return res.status(403).json({ message: 'Invalid token structure' });
      }
      
      req.user = decoded.user;
      next();
    });
  };