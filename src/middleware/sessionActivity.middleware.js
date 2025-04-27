import User from "../models/user.model.js";
import logger from "../logger/winston.logger.js";

// Middleware
import asyncHandler from "../middleware/asyncHandler.middleware.js";

const SessionActivity = asyncHandler(async (req, _, next) => {
  const token = req.cookies?.accessToken;

  if (token) {
    try {
      const user = await User.findOne({
        "sessions.token": token,
      }).select("+sessions");

      if (user) {
        const now = new Date();
        const idleThreshold = new Date(now.getTime() - 30 * 60000);

        // Remove sessions that were idle too long
        user.sessions = user.sessions.filter((s) => s.lastUsed > idleThreshold);

        // Update lastUsed for current session
        const session = user.sessions.find((s) => s.token === token);
        if (session) {
          session.lastUsed = now;
        }

        await user.save({ validateBeforeSave: false });
      }
    } catch (error) {
      logger.error("Session activity update failed:", error);
    }
  }

  next();
});

export default SessionActivity;
