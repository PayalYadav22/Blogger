// Port on which the server will listen; fetched from environment variables
export const PORT = process.env.PORT;

// MongoDB connection URI string (includes credentials and cluster details); stored securely in environment variables
export const MONGO_URI = process.env.MONGO_URI;

// Name of the MongoDB database to connect to; fetched from environment variables
export const MONGO_DB = process.env.MONGO_DB;

// Allowed origin(s) for Cross-Origin Resource Sharing (CORS); restricts frontend domains that can access the API
export const CORS_ORIGIN = process.env.CORS_ORIGIN;

// Email ID used for sending emails (e.g., verification, password reset); fetched from environment variables for security
export const EMAIL_ID = process.env.EMAIL_ID;

// Corresponding password or app-specific password for the email account; should be kept secure and not exposed
export const EMAIL_PASSWORD = process.env.EMAIL_PASSWORD;

// Number of salt rounds to use with bcrypt for hashing passwords; higher value increases security but also slows down hashing
export const SALT_ROUND = 12;

// OTP expiration time; time in milliseconds (5 minutes)
export const OTP_EXPIRATION_TIME = new Date(Date.now() + 15 * 60 * 1000);

// Security-related configuration
export const SECURITY_CONFIG = {
  // Maximum number of OTP attempts before blocking further attempts
  MAX_OTP_ATTEMPTS: 5,

  // Duration for which OTP attempts will be blocked after reaching the maximum limit (15 minutes)
  OTP_BLOCK_DURATION: 15 * 60 * 1000,

  // Maximum number of failed login attempts before locking the account
  MAX_FAILED_LOGINS: 5,

  // Duration for which login attempts are blocked after reaching the maximum number of failed attempts (15 minutes)
  LOGIN_BLOCK_DURATION: 15 * 60 * 1000,

  // Limit the number of stored previous passwords to avoid excessive data retention
  PASSWORD_HISTORY_LIMIT: 5,

  // Prevent reusing the same password for the specified cooldown period (1 year in milliseconds)
  PASSWORD_REUSE_COOLDOWN: 365 * 24 * 60 * 60 * 1000,
};

// Cloudinary API credentials; used for media storage (avatars, images)
export const CLOUDINARY_API_KEY = process.env.CLOUDINARY_API_KEY;
export const CLOUDINARY_NAME = process.env.CLOUDINARY_NAME;
export const CLOUDINARY_API_SECRET = process.env.CLOUDINARY_API_SECRET;

// Cookie options for authentication tokens (e.g., refresh tokens)
export const OPTIONS = {
  httpOnly: true, // Cookie not accessible via JavaScript (mitigates XSS)
  secure: process.env.NODE_ENV === "production", // Only HTTPS in production
  sameSite: "strict", // No cross-site cookie sharing
  maxAge: 24 * 60 * 60 * 1000, // 1 day
};

// JWT (JSON Web Token) secrets and expiration times
export const JWT_ACCESS_SECRET = process.env.JWT_ACCESS_SECRET;
export const JWT_ACCESS_SECRET_EXPIRESIN =
  process.env.JWT_ACCESS_SECRET_EXPIRESIN;
export const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET;
export const JWT_REFRESH_SECRET_EXPIRESIN =
  process.env.JWT_REFRESH_SECRET_EXPIRESIN;

// Base URL for client application (frontend); needed for CORS, redirects, etc.
export const CLIENT_BASE_URL = process.env.CLIENT_BASE_URL;

// Twilio credentials; used for sending OTPs via SMS
export const TWILIO_ACCOUNT_SID = process.env.TWILIO_ACCOUNT_SID;
export const TWILIO_AUTH_TOKEN = process.env.TWILIO_AUTH_TOKEN;
export const TWILIO_PHONE_NUMBER = process.env.TWILIO_PHONE_NUMBER;

// Idle timeout setting (in minutes) for user sessions
export const IDLE_TIMEOUT_MINUTES = 180;

// Limit the number of stored password histories globally (this is duplicated inside SECURITY_CONFIG too)
export const PASSWORD_HISTORY_LIMIT = 5;

// Google reCAPTCHA credentials; used for bot protection
export const GOOGLE_SITE_KEY = process.env.GOOGLE_SITE_KEY;
export const GOOGLE_SECRET_KEY = process.env.GOOGLE_SECRET_KEY;

export const MAX_OTP_ATTEMPTS = 5;
export const BLOCK_DURATION_MS = 10 * 60 * 1000;

export const BODY_SIZE_LIMIT = "10mb";
export const VIEW_LIMIT_DURATION = 30 * 60 * 1000;
