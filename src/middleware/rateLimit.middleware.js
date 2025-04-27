import rateLimit from "express-rate-limit";
import User from "../models/user.model.js";

const getRateLimit = async (ip) => {
  const failedAttempts = await getFailedLoginAttempts(ip);
  let limit = 10;

  if (failedAttempts > 5) {
    limit = 5;
  } else if (failedAttempts > 2) {
    limit = 7;
  }

  return limit;
};

export const authLimiter = async (req, res, next) => {
  const ip = req.ip;
  const maxRequests = await getRateLimit(ip);

  const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: maxRequests,
    message: "Too many requests from this IP, please try again later",
    skipSuccessfulRequests: true,
  });

  limiter(req, res, next);
};

async function getFailedLoginAttempts(ip) {
  const user = await User.findOne({ "lastLoginAttempt.ip": ip });
  return user ? user.failedLoginAttempts : 0;
}

export const passwordResetLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3,
  message: "Too many password reset attempts, please try again later",
});
