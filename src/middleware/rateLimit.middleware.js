import rateLimit from "express-rate-limit";
import User from "../models/user.model.js";

// Basic limiter instances
const normalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10,
  message: "Too many requests from this IP, please try again later",
  skipSuccessfulRequests: true,
});

const mediumLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 7,
  message: "Too many requests from this IP, please try again later",
  skipSuccessfulRequests: true,
});

const strictLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: "Too many requests from this IP, please try again later",
  skipSuccessfulRequests: true,
});

// Helper to check IP and choose a limiter
async function selectLimiter(req, res, next) {
  const ip = req.ip;
  const failedAttempts = await getFailedLoginAttempts(ip);

  if (failedAttempts > 5) {
    return strictLimiter(req, res, next);
  } else if (failedAttempts > 2) {
    return mediumLimiter(req, res, next);
  } else {
    return normalLimiter(req, res, next);
  }
}

// Exported middleware
export const authLimiter = (req, res, next) => {
  selectLimiter(req, res, next).catch(next);
};

async function getFailedLoginAttempts(ip) {
  const user = await User.findOne({ "lastLoginAttempt.ip": ip });
  return user ? user.failedLoginAttempts : 0;
}

// Password reset limiter
export const passwordResetLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3,
  message: "Too many password reset attempts, please try again later",
});

// Registration limiter
export const registerLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: {
    status: 429,
    message:
      "Too many registration attempts from this IP. Please try again later.",
  },
  standardHeaders: true,
  legacyHeaders: false,
});
