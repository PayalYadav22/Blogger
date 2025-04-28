/**
 * @copyright 2025 Payal Yadav
 * @license Apache-2.0
 */

// External Packages
import jwt from "jsonwebtoken";
import { StatusCodes } from "http-status-codes";

// Models
import User from "../models/user.model.js";

// Middleware
import asyncHandler from "../middleware/asyncHandler.middleware.js";

// Constants
import {
  JWT_ACCESS_SECRET,
  IDLE_TIMEOUT_MINUTES,
} from "../constants/constant.config.js";

// Utils
import ApiError from "../utils/apiError.js";
import logger from "../logger/winston.logger.js";

// ------------------------------
// Authentication Middleware
// ------------------------------

const authenticate = asyncHandler(async (req, _, next) => {
  // Get the token from cookies or headers
  const token =
    req.cookies?.accessToken ||
    req.header("Authorization")?.replace("Bearer ", "");

  if (!token) {
    logger.warn("AuthMiddleware: No token provided");
    throw new ApiError(StatusCodes.UNAUTHORIZED, "Authentication required");
  }

  try {
    // Verify the JWT token
    const decoded = jwt.verify(token, JWT_ACCESS_SECRET);

    // Find the user by ID
    const user = await User.findById(decoded._id).select(
      "-password -tokens.token -otp"
    );

    if (!user) {
      logger.warn("AuthMiddleware: User not found");
      throw new ApiError(StatusCodes.UNAUTHORIZED, "User not found");
    }

    // Token Binding Check (Security Enhancement)
    if (
      (decoded.userAgent && decoded.userAgent !== req.headers["user-agent"]) ||
      (decoded.ipAddress && decoded.ipAddress !== req.ip)
    ) {
      logger.warn("AuthMiddleware: Token binding mismatch");
      throw new ApiError(
        StatusCodes.UNAUTHORIZED,
        "Session verification failed"
      );
    }

    // Password Change Check (Security Enhancement)
    if (user.passwordChangedAt) {
      const passwordChangedAtTime = Math.floor(
        new Date(user.passwordChangedAt).getTime() / 1000
      );
      if (decoded.iat < passwordChangedAtTime) {
        logger.warn("AuthMiddleware: Token issued before password change");
        throw new ApiError(
          StatusCodes.UNAUTHORIZED,
          "Password changed recently. Please login again."
        );
      }
    }

    // Idle Session Timeout Check
    if (user.lastActivityAt) {
      const now = Date.now();
      const lastActive = new Date(user.lastActivityAt).getTime();
      const minutesInactive = (now - lastActive) / (1000 * 60);

      if (minutesInactive > IDLE_TIMEOUT_MINUTES) {
        logger.warn("AuthMiddleware: Idle timeout - session expired");
        throw new ApiError(
          StatusCodes.UNAUTHORIZED,
          "Session expired due to inactivity"
        );
      }
    }

    // Update lastActivityAt on every request
    user.lastActivityAt = new Date();
    await user.save({ validateBeforeSave: false });

    // Attach user and session info to request
    req.user = user;
    req.sessionId = decoded.sessionId || null;

    // Move to the next middleware or route handler
    next();
  } catch (error) {
    // Token expired or invalid token errors
    if (error instanceof jwt.TokenExpiredError) {
      logger.warn("AuthMiddleware: Token expired");
      throw new ApiError(StatusCodes.UNAUTHORIZED, "Token expired");
    }
    if (error instanceof jwt.JsonWebTokenError) {
      logger.warn("AuthMiddleware: Invalid token");
      throw new ApiError(StatusCodes.UNAUTHORIZED, "Invalid token");
    }

    // Unexpected error handling
    logger.error(`AuthMiddleware: Unexpected error - ${error.message}`);
    throw new ApiError(StatusCodes.UNAUTHORIZED, "Authentication failed");
  }
});

export default authenticate;
