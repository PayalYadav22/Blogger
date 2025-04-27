import { StatusCodes } from "http-status-codes";
import ApiError from "../utils/apiError.js";

const MAX_FILE_SIZE = 20 * 1024 * 1024;

const ALLOWED_MIME_TYPES = [
  "image/jpeg",
  "image/png",
  "image/gif",
  "image/webp",
];

const validateFile = (req, _, next) => {
  if (!req.file) return next();

  if (req.file.size > MAX_FILE_SIZE) {
    return next(new ApiError(StatusCodes.BAD_REQUEST, "File too large"));
  }

  if (!ALLOWED_MIME_TYPES.includes(req.file.mimetype)) {
    return next(new ApiError(StatusCodes.BAD_REQUEST, "Invalid file type"));
  }

  next();
};

export default validateFile;
