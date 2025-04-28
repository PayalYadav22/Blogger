import { StatusCodes } from "http-status-codes";
import ApiError from "../utils/apiError.js";

const authorizeRoles = (...allowedRoles) => {
  return (req, _, next) => {
    const userRole = req.user?.role;

    if (!userRole) {
      return next(new ApiError(StatusCodes.NOT_FOUND, "User role not found"));
    }

    if (!allowedRoles.includes(userRole)) {
      return next(
        new ApiError(
          StatusCodes.FORBIDDEN,
          "You are not authorized to access this resource"
        )
      );
    }
    next();
  };
};

export default authorizeRoles;
