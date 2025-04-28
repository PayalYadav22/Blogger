import express from "express";
import AuthController from "../controllers/auth/auth.controller.js";
import upload from "../middleware/multer.middleware.js";
import {
  authLimiter,
  registerLimiter,
  passwordResetLimiter,
} from "../middleware/rateLimit.middleware.js";
import validateFile from "../middleware/validateFile.middleware.js";
import authenticate from "../middleware/authenticate.middleware.js";
import require2FA from "../middleware/require2FA.middleware.js";
import SessionActivity from "../middleware/sessionActivity.middleware.js";
import validate from "../middleware/validate.middleware.js";
import { registerValidUser } from "../validation/user.validation.js";
const router = express.Router();

/* ------------------------------- Public Routes ------------------------------- */

// User registration (with avatar upload, file validation, and rate limiting)
router
  .route("/register")
  .post(
    upload.single("avatar"),
    registerLimiter,
    validateFile,
    validate(registerValidUser),
    AuthController.registerUser
  );

// Email verification
router.route("/verify-email").post(AuthController.verifyEmail);

// User login (with rate limiting)
router.route("/login").post(authLimiter, AuthController.loginUser);

// QR-based login (with rate limiting)
router.route("/qr-login").post(authLimiter, AuthController.loginQrBaseUser);

// Forgot password (send reset OTP, with rate limiting)
router
  .route("/forgot-password")
  .post(passwordResetLimiter, AuthController.forgotPassword);

// Reset password via OTP (with rate limiting)
router
  .route("/reset-password-otp")
  .patch(passwordResetLimiter, AuthController.resetPasswordWithOtp);

// Reset password via token link (with rate limiting)
router
  .route("/reset-password/:token")
  .patch(passwordResetLimiter, AuthController.resetPasswordWithToken);

// Refresh OTP or QR code (no rate limiting)
router.route("/refresh-otp").post(AuthController.refreshOTP);
router.route("/refresh-qr-code").post(AuthController.refreshQrCode);

// Refresh authentication token
router.route("/refresh-token").get(AuthController.refreshToken);

/* ------------------------------- Protected Routes ------------------------------- */

// Apply authentication, two-factor authentication, and session activity tracking middleware
router.use(authenticate, require2FA, SessionActivity);

// Logout user
router.route("/logout").get(AuthController.logoutUser);

// Get active sessions or update current session
router
  .route("/sessions")
  .get(AuthController.getActiveSessions)
  .patch(AuthController.currentSession);

// Revoke a single session
router.route("/sessions/revoke").delete(AuthController.revokeSession);

// Revoke all active sessions
router.route("/sessions/revoke-all").delete(AuthController.revokeAllSessions);

export default router;
