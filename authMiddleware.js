import jwt from 'jsonwebtoken';

export const verifyToken = (req, res, next) => {
  const header = req.headers.authorization;
  if (!header) return res.status(403).json({ message: '🔒 لا يوجد توكن' });

  const token = header.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ message: '❌ Invalid token'});
  }
};
