// Middleware
import asyncHandler from "../middleware/asyncHandler.middleware.js";

// Utils
import ApiError from "../utils/apiError.js";

const require2FA = asyncHandler(async (req, _, next) => {
  const { is2faVerified, has2FA } = req.user;

  if (has2FA && !is2faVerified) {
    throw new ApiError(
      StatusCodes.FORBIDDEN,
      "Two-factor authentication is required for this operation."
    );
  }

  next();
});

export default require2FA;
