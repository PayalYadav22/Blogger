// External Packages
import mongoose from "mongoose";
import speakeasy from "speakeasy";
import QRCode from "qrcode";
import * as UAParser from "ua-parser-js";
import { StatusCodes } from "http-status-codes";

// Models
import User from "../../models/user.model.js";

// Configurations
import {
  uploadFileToCloudinary,
  deleteFileFromCloudinary,
} from "../../config/cloudinary.config.js";

// Constants
import { OPTIONS } from "../../constants/constant.config.js";

// Middleware
import asyncHandler from "../../middleware/asyncHandler.middleware.js";

// Utilities
import ApiError from "../../utils/apiError.js";
import ApiResponse from "../../utils/apiResponse.js";
import generateOTP from "../../utils/otp.js";
import sendEmail from "../../utils/email.js";

const generateTokens = async (id, ip, device, deviceFingerprint, req) => {
  try {
    const user = await User.findById(id);

    if (!user) {
      throw new ApiError(StatusCodes.NOT_FOUND, "User not found");
    }

    // Generate tokens
    const accessToken = await user.generateAccessToken();
    const refreshToken = await user.generateRefreshToken(req);

    user.sessions.push({
      token: accessToken,
      refreshToken: refreshToken,
      ip: ip || null,
      device: device || null,
      createdAt: new Date(),
      lastUsed: new Date(),
      deviceFingerprint: deviceFingerprint || {},
    });

    await user.save({ validateBeforeSave: false });

    return { accessToken, refreshToken };
  } catch (error) {
    throw new ApiError(
      StatusCodes.INTERNAL_SERVER_ERROR,
      "Authentication service unavailable"
    );
  }
};

const deviceFingerprint = (req) => {
  const parser = new UAParser.UAParser(req.headers["user-agent"]);
  const result = parser.getResult();

  const fingerprint = {
    browser:
      result.browser?.name && result.browser?.version
        ? `${result.browser.name} ${result.browser.version}`
        : "Unknown Browser",
    os:
      result.os?.name && result.os?.version
        ? `${result.os.name} ${result.os.version}`
        : "Unknown OS",
    device: result.device?.type || "desktop",
    platform: result.platform?.type || "unknown",
  };

  return fingerprint;
};

const AuthController = {
  // Controller to handle new user registration
  registerUser: asyncHandler(async (req, res) => {
    // Step 1: Extract required fields from the request body
    const {
      email,
      userName,
      fullName,
      phone,
      password,
      bio,
      gender,
      dateOfBirth,
      socialLinks,
    } = req.body;

    // Step 2: Basic validation - Ensure all mandatory fields are present
    if (
      [email, userName, fullName, phone, password].some(
        (field) => !field?.toString().trim()
      )
    ) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Full name, email, username, phone number, and password are required."
      );
    }

    // Step 3: Check for duplicates - Prevent registration with existing email/username/phone
    const existingUser = await User.findOne({
      $or: [{ email }, { userName }, { phone }],
    });
    if (existingUser) {
      throw new ApiError(
        StatusCodes.CONFLICT,
        "A user with the provided email, username, or phone number already exists."
      );
    }

    // Step 4: Avatar handling - Validate and upload user profile picture
    const avatarLocalPath = req?.file?.path;
    if (!avatarLocalPath) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Avatar image is required during registration."
      );
    }

    const avatar = await uploadFileToCloudinary(avatarLocalPath);
    if (!avatar?.secure_url || !avatar?.public_id) {
      if (avatar?.public_id) await deleteFileFromCloudinary(avatar.public_id);
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Failed to upload and process profile image."
      );
    }

    // Step 5: Prepare user data - Generate OTP for email verification
    const otp = generateOTP();
    const otpExpiration = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes from now

    // Step 6: Create user in the database
    const user = await User.create({
      fullName,
      email,
      userName,
      password,
      phone,
      bio,
      gender,
      dateOfBirth,
      avatar: {
        publicId: avatar.public_id,
        url: avatar.secure_url,
      },
      socialLinks,
      otp,
      otpExpiration,
      ...req.body, // (Optional) Spread additional allowed fields
    });

    if (!user) {
      await deleteFileFromCloudinary(avatar.public_id);
      throw new ApiError(
        StatusCodes.INTERNAL_SERVER_ERROR,
        "Failed to create user. Please try again later."
      );
    }

    // Step 7: Set up Two-Factor Authentication (2FA) for enhanced security
    const secret = speakeasy.generateSecret({
      name: `Blogger (${user.email})`,
    });
    user.scannerSecret = secret.base32;
    user.qrCode = await QRCode.toDataURL(secret.otpauth_url);

    // Step 8: Generate backup codes for 2FA recovery
    user.generateBackupCodes();

    // Save user updates (2FA secret and codes) without re-triggering all validations
    await user.save({ validateBeforeSave: false });

    // Step 9: Send OTP verification email
    try {
      await sendEmail({
        to: user.email,
        subject: "Verify Your Email",
        template: "emailVerification",
        context: {
          name: user.fullName,
          otp: otp,
          expiresIn: "10 minutes",
        },
      });
    } catch (error) {
      // Rollback - Delete avatar and user if email fails
      await Promise.all([
        deleteFileFromCloudinary(user.avatar.publicId),
        User.findByIdAndDelete(user._id),
      ]);
      throw new ApiError(
        StatusCodes.INTERNAL_SERVER_ERROR,
        "User created but failed to send verification email. Please contact support."
      );
    }

    // Step 10: Respond with user details (excluding sensitive info)
    return new ApiResponse(
      StatusCodes.OK,
      {
        userId: user._id,
        fullName: user.fullName,
        userName: user.userName,
        email: user.email,
        avatar: user.avatar?.url,
        phone: user.phone,
        gender: user.gender,
        dateOfBirth: user.dateOfBirth,
        bio: user.bio,
        role: user.role,
        socialLinks: user.socialLinks,
        qrCode: user.qrCode, // Frontend will display this for 2FA setup
      },
      "Registration successful! Please verify your email to activate your account."
    ).send(res);
  }),

  // Controller to verify user's email with OTP
  verifyEmail: asyncHandler(async (req, res) => {
    const { email, otp } = req.body;

    // Step 1: Basic input validation
    if (!email || !otp) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Both email and OTP are required for verification."
      );
    }

    // Step 2: Fetch user by email and check OTP eligibility
    const user = await User.findOne({
      email,
      otp: { $exists: true },
      otpExpiration: { $gt: Date.now() }, // OTP must not be expired
      isEmailVerified: false, // Only allow unverified users
    }).select("+password +otp +otpExpiration +otpAttempts +otpBlockedUntil"); // Explicitly select protected fields

    if (!user) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Invalid or expired OTP. Please request a new one."
      );
    }

    // Step 3: Check if user is currently blocked due to too many failed attempts
    if (user.otpBlockedUntil && user.otpBlockedUntil > Date.now()) {
      const remainingMinutes = Math.ceil(
        (user.otpBlockedUntil - Date.now()) / (60 * 1000)
      );
      throw new ApiError(
        StatusCodes.TOO_MANY_REQUESTS,
        `Too many failed attempts. Please try again in ${remainingMinutes} minute(s).`
      );
    }

    // Step 4: Validate the provided OTP against user's stored OTP
    const isValid = await user.compareOTP(otp);

    if (!isValid) {
      // Step 4a: Handle incorrect OTP attempt
      user.otpAttempts += 1;

      // Block user if failed attempts exceed limit
      if (user.otpAttempts >= 5) {
        user.otpBlockedUntil = new Date(Date.now() + 10 * 60 * 1000); // Block for 10 minutes
      }

      await user.save({ validateBeforeSave: false });

      const attemptsLeft = Math.max(0, 5 - user.otpAttempts);

      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        attemptsLeft > 0
          ? `Incorrect OTP. You have ${attemptsLeft} attempt(s) left.`
          : "Too many incorrect attempts. Please try again after 10 minutes."
      );
    }

    // Step 5: Begin transaction to verify email safely
    const session = await mongoose.startSession();

    try {
      session.startTransaction();

      // Mark email as verified
      user.isEmailVerified = true;
      user.emailVerifiedAt = new Date();

      // Step 5a: Cleanup sensitive OTP fields
      user.otp = undefined;
      user.otpExpiration = undefined;
      user.otpAttempts = 0;
      user.otpBlockedUntil = undefined;
      user.emailVerificationToken = undefined;
      user.emailVerificationTokenExpiration = undefined;

      // Save the user within transaction
      await user.save({ session });

      // Step 6: Commit transaction after successful save
      await session.commitTransaction();

      // Step 7: Respond with success
      return new ApiResponse(
        StatusCodes.OK,
        { isEmailVerified: true },
        "Your email has been successfully verified."
      ).send(res);
    } catch (error) {
      // Step 8: Abort transaction in case of any error
      await session.abortTransaction();

      // Log error details for debugging
      console.error("Error during email verification session:", error);

      throw new ApiError(
        StatusCodes.INTERNAL_SERVER_ERROR,
        "Something went wrong during verification. Please try again."
      );
    } finally {
      // Step 9: Always end session
      session.endSession();
    }
  }),

  // Controller to log in a user
  loginUser: asyncHandler(async (req, res) => {
    const {
      email,
      userName,
      phone,
      password,
      screenResolution,
      timezone,
      language,
    } = req.body;

    // Step 1: Validate input - require password and at least one identifier
    if (!password || (!email && !userName && !phone)) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Password and at least one of email, username, or phone number must be provided."
      );
    }

    // Step 2: Find user by email, username, or phone
    const user = await User.findOne({
      $or: [{ email }, { userName }, { phone }],
    }).select(
      "+password +isActive +isSuspended +isEmailVerified +accountLockTime +failedLoginAttempts +lastLoginAttempt +twoFactorEnabled +scannerSecret +twoFactorBackupCodes +sessions"
    );

    // Step 3: Handle user not found - add delay to mitigate user enumeration attacks
    if (!user) {
      await new Promise((resolve) => setTimeout(resolve, 500));
      throw new ApiError(StatusCodes.UNAUTHORIZED, "Invalid credentials.");
    }

    // Step 4: Validate the provided password
    const isValid = await user.comparePassword(password);

    if (!isValid) {
      // Step 4a: Register failed attempt and delay response
      await user.registerFailedLogin();
      await new Promise((resolve) => setTimeout(resolve, 500));
      throw new ApiError(StatusCodes.UNAUTHORIZED, "Invalid credentials.");
    }

    // Step 5: Check account status flags
    if (!user.isActive) {
      throw new ApiError(
        StatusCodes.FORBIDDEN,
        "This account has been deactivated."
      );
    }

    if (user.isSuspended) {
      throw new ApiError(
        StatusCodes.FORBIDDEN,
        "This account is currently suspended."
      );
    }

    if (!user.isEmailVerified) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Please verify your email before logging in."
      );
    }

    // Step 6: Check if user is temporarily locked out due to too many failed attempts
    if (!(await user.canAttemptLogin())) {
      const remainingMinutes = Math.ceil(
        (user.accountLockTime - Date.now()) / (60 * 1000)
      );
      throw new ApiError(
        StatusCodes.TOO_MANY_REQUESTS,
        `Too many failed attempts. Please try again in ${remainingMinutes} minute(s).`
      );
    }

    // Step 7: Parse device/browser info for session tracking
    const Fingerprint = deviceFingerprint(req);

    // Step 8: Generate access and refresh tokens
    const { accessToken, refreshToken } = await generateTokens(
      user._id,
      req.ip,
      req.headers["user-agent"],
      Fingerprint,
      req
    );

    // Step 9: Reset login attempts and log new session
    await User.findByIdAndUpdate(
      user._id,
      {
        $set: {
          loginAttempts: 0,
          lockUntil: undefined,
          lastLogin: {
            ip: req.ip,
            device: req.headers["user-agent"],
            timestamp: new Date(),
          },
        },
        $push: {
          sessions: {
            ipAddress: req.ip,
            userAgent: req.headers["user-agent"],
            deviceFingerprint,
            createdAt: new Date(),
          },
        },
      },
      { validateBeforeSave: false, new: true }
    );

    // Step 10: Set secure, HTTP-only cookies for tokens
    res
      .cookie("accessToken", accessToken, OPTIONS)
      .cookie("refreshToken", refreshToken, OPTIONS);

    // Step 11: Send successful login response with minimal safe user info
    return new ApiResponse(
      StatusCodes.OK,
      {
        userId: user._id,
        fullName: user.fullName,
        userName: user.userName,
        email: user.email,
        avatar: user.avatar?.url,
        phone: user.phone,
        gender: user.gender,
        dateOfBirth: user.dateOfBirth,
        bio: user.bio,
        role: user.role,
        socialLinks: user.socialLinks,
        tokens: {
          accessToken,
          refreshToken,
        },
      },
      "Login successful. Welcome back!"
    ).send(res);
  }),

  // Controller for QR Code-based Login for User
  loginQrBaseUser: asyncHandler(async (req, res) => {
    const { email, token } = req.body;

    // Validate input
    if (!email || !token) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Email and Token are required to log in."
      );
    }

    // Fetch user and sensitive fields (scannerSecret, otp, otpExpiration)
    const user = await User.findOne({ email }).select(
      "+scannerSecret +otp +otpExpiration"
    );

    // Check if user exists and has 2FA setup
    if (!user || !user.scannerSecret) {
      throw new ApiError(
        StatusCodes.NOT_FOUND,
        "User not found or OTP is not set up. Please enable two-factor authentication first."
      );
    }

    // Verify the provided token with user's scannerSecret
    const isVerified = speakeasy.totp.verify({
      secret: user.scannerSecret,
      encoding: "base32",
      token,
      window: 1, // allow 1 step window before/after
    });

    // If token verification fails
    if (!isVerified) {
      throw new ApiError(StatusCodes.UNAUTHORIZED, "Invalid or expired token.");
    }

    try {
      // Reset login-related fields
      user.resetLoginState(req.ip, req.headers["user-agent"]);

      // Save updated user state
      await user.save({ validateBeforeSave: false });

      // Generate access and refresh tokens
      const Fingerprint = deviceFingerprint(req);
      const { accessToken, refreshToken } = await generateTokens(
        user._id,
        req.ip,
        req.headers["user-agent"],
        Fingerprint,
        req
      );

      // Set tokens in secure cookies
      res.cookie("accessToken", accessToken, OPTIONS);
      res.cookie("refreshToken", refreshToken, OPTIONS);

      // Respond with user profile and tokens
      return new ApiResponse(
        StatusCodes.OK,
        {
          userId: user._id,
          fullName: user.fullName,
          userName: user.userName,
          email: user.email,
          avatar: user.avatar?.url,
          phone: user.phone,
          gender: user.gender,
          dateOfBirth: user.dateOfBirth,
          bio: user.bio,
          role: user.role,
          socialLinks: user.socialLinks,
          tokens: {
            accessToken,
            refreshToken,
          },
        },
        "Authentication successful. You are now logged in."
      ).send(res);
    } catch (error) {
      console.error("Login error:", error);
      throw new ApiError(StatusCodes.INTERNAL_SERVER_ERROR, "Failed to login.");
    }
  }),

  // Controller for Forgot Password functionality for User
  forgotPassword: asyncHandler(async (req, res) => {
    const { email } = req.body;

    // Check if email is provided in the request body
    if (!email) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Email is required.");
    }

    // Find user by email, including the OTP and OTP expiration fields
    const user = await User.findOne({ email }).select("+otp +otpExpiration");

    // If user is not found, throw an error
    if (!user) {
      throw new ApiError(StatusCodes.NOT_FOUND, "User not found.");
    }

    // Generate a new password reset token and OTP for the user
    const resetToken = user.generatePasswordResetToken(); // Use the method to generate the reset token
    const otp = generateOTP(); // OTP generation logic
    const otpExpiration = new Date(Date.now() + 15 * 60 * 1000); // OTP expiration in 15 minutes

    // Assign generated OTP and expiration to the user
    user.otp = otp;
    user.otpExpiration = otpExpiration;

    // Assign the reset token and expiration to the user
    user.passwordResetToken = resetToken;
    user.passwordResetTokenExpiration = Date.now() + 15 * 60 * 1000; // Token expiration in 15 minutes

    // Save the updated user details, without validation before saving
    await user.save({ validateBeforeSave: false });

    // Generate the password reset URL with the reset token
    const resetUrl = `http://localhost:3000/api/v1/auth/reset-password?token=${resetToken}`;

    // Send the password reset email to the user with OTP and reset URL
    await sendEmail({
      to: user.email,
      subject: "Password Reset Request",
      template: "passwordReset",
      context: {
        name: user.fullName, // Pass user's full name to the email template
        otp: otp, // Pass generated OTP to the email template
        resetUrl: resetUrl, // Pass the password reset URL to the email template
        expiresIn: "15 minutes", // Inform the user the OTP and link will expire in 15 minutes
      },
    });

    // Return a successful response with the reset URL
    return new ApiResponse(
      StatusCodes.OK,
      { resetUrl },
      "OTP and Password Reset link sent to your email."
    ).send(res);
  }),

  // Controller for Reset Password Using OTP functionality for User
  resetPasswordWithOtp: asyncHandler(async (req, res) => {
    // Extract required fields from request body
    const { email, otp, newPassword, confirmPassword } = req.body;

    // Check if all fields are provided
    if ([email, otp, newPassword, confirmPassword].some((field) => !field)) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Please provide all the required fields: email, OTP, new password, and confirm password."
      );
    }

    // Check if newPassword and confirmPassword match
    if (newPassword !== confirmPassword) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Passwords do not match.");
    }

    // Find user by email and select otp-related fields explicitly
    const user = await User.findOne({ email }).select("+otp +otpExpiration");

    // If user not found, throw error
    if (!user) {
      throw new ApiError(StatusCodes.NOT_FOUND, "User not found.");
    }

    // Validate provided OTP
    const isValid = await user.compareOTP(otp);

    // If OTP is invalid or expired, throw error
    if (!isValid) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid or expired OTP.");
    }

    // OTP is valid: reset the password and clear OTP-related fields
    user.password = newPassword;
    user.otp = undefined;
    user.otpExpiration = undefined;
    user.passwordResetToken = undefined;

    // Save updated user details
    await user.save();

    // Send success response
    return new ApiResponse(
      StatusCodes.OK,
      "Password reset successfully via OTP."
    ).send(res);
  }),

  // Controller to reset password using reset token
  resetPasswordWithToken: asyncHandler(async (req, res) => {
    // Extract token from URL parameters
    const { token } = req.params;
    // Extract required fields from request body
    const { email, newPassword, confirmPassword } = req.body;

    // Validate required inputs
    if (!token) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Token is required.");
    }

    if (!email) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Email is required.");
    }

    if (!newPassword || !confirmPassword) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Both new password and confirm password are required."
      );
    }

    // Ensure new password and confirm password match
    if (newPassword !== confirmPassword) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Passwords do not match.");
    }

    // Find user by email and validate token and its expiration
    const user = await User.findOne({
      email,
      passwordResetToken: token,
      passwordResetTokenExpiration: { $gt: new Date() }, // Check if token is still valid (not expired)
    }).select(
      "+otp +otpExpiration +passwordResetToken +passwordResetTokenExpiration" // Select additional fields required
    );

    // If user not found or token invalid/expired
    if (!user) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Invalid or expired reset token."
      );
    }

    // Update user's password and clear password reset fields
    user.password = newPassword;
    user.passwordResetToken = undefined;
    user.passwordResetTokenExpiration = undefined;
    user.otp = undefined;
    user.otpExpiration = undefined;

    // Save updated user document
    await user.save();

    // Send success response
    return new ApiResponse(
      StatusCodes.OK,
      "Password reset successfully via link."
    ).send(res);
  }),

  // Controller to log out a user
  logoutUser: asyncHandler(async (req, res) => {
    const refreshToken = req?.cookies?.refreshToken;
    const accessToken = req?.cookies?.accessToken;

    // Step 1: Validate that a refresh token is provided
    if (!refreshToken) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Refresh token required");
    }

    // Step 2: Authenticate user using the refresh token
    const user = await User.authenticateToken(refreshToken);

    // Step 3: Handle invalid or expired refresh token
    if (!user) {
      throw new ApiError(StatusCodes.UNAUTHORIZED, "Invalid refresh token.");
    }

    // Step 4: Remove the used refresh token from user's stored tokens
    user.refreshTokens = user.refreshTokens.filter(
      (tokenObj) => tokenObj.token !== refreshToken
    );

    // Step 5: Also remove the matching session if access token is available
    if (accessToken) {
      user.sessions = user.sessions.filter(
        (session) => session.token !== accessToken
      );
    }

    // Step 6: Invalidate two-factor authentication status
    user.is2faVerified = false;

    // Step 7: Save the updated user without triggering full validations
    await user.save({ validateBeforeSave: false });

    // Step 8: Clear authentication cookies
    res.clearCookie("refreshToken", OPTIONS);
    res.clearCookie("accessToken", OPTIONS);

    // Step 9: Send logout success response
    return new ApiResponse(StatusCodes.OK, "Logged out successfully").send(res);
  }),

  // Controller to refresh user token
  refreshToken: asyncHandler(async (req, res) => {
    // Step 1: Extract the refresh token from cookies
    const token = req.cookies?.refreshToken;

    // Step 2: Validate the presence of the refresh token
    if (!token) {
      throw new ApiError(
        StatusCodes.UNAUTHORIZED,
        "No refresh token provided."
      );
    }

    // Step 3: Verify and authenticate the user based on the refresh token
    let user;
    try {
      user = await User.authenticateToken(token);
    } catch (error) {
      throw new ApiError(StatusCodes.UNAUTHORIZED, "Invalid refresh token.");
    }

    // Step 4: Ensure the user exists and the token is valid
    if (!user) {
      throw new ApiError(StatusCodes.UNAUTHORIZED, "Invalid refresh token.");
    }

    // Step 5: Check whether the provided refresh token exists in user's stored tokens
    const tokenExists = user.refreshTokens.some((t) => t.token === token);

    if (!tokenExists) {
      throw new ApiError(
        StatusCodes.UNAUTHORIZED,
        "Refresh token is not valid."
      );
    }

    // Step 6: Generate device fingerprint based on the incoming request
    const Fingerprint = deviceFingerprint(req);

    // Step 7: Issue new access and refresh tokens for the authenticated user
    const { accessToken, refreshToken } = await generateTokens(
      user._id,
      req.ip,
      req.headers["user-agent"],
      Fingerprint,
      req
    );

    // Step 8: Remove the old (used) refresh token from the database
    await User.findByIdAndUpdate(
      user._id,
      {
        $pull: { refreshTokens: { token } },
      },
      { new: true, validateBeforeSave: false }
    );

    // Step 9: Store the newly issued refresh token along with metadata
    await User.findByIdAndUpdate(
      user._id,
      {
        $push: {
          refreshTokens: {
            token: refreshToken,
            createdAt: new Date(),
            expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days validity
          },
        },
      },
      { new: true, validateBeforeSave: false }
    );

    // Step 10: Set the new access and refresh tokens in the response cookies
    res.cookie("accessToken", accessToken, OPTIONS);
    res.cookie("refreshToken", refreshToken, OPTIONS);

    // Step 11: Update the user's session data
    const currentToken = req.cookies?.accessToken;

    if (currentToken) {
      // Remove the previous session associated with the old access token
      user.sessions = user.sessions.filter((s) => s.token !== currentToken);

      // Append the new session details
      user.sessions.push({
        token: accessToken,
        refreshToken,
        ip: req.ip,
        device: req.headers["user-agent"] || "unknown",
      });

      // Retain only the latest 10 active sessions for security and performance
      if (user.sessions.length > 10) {
        user.sessions = user.sessions.slice(-10);
      }

      // Persist the updated sessions to the database
      await user.save({ validateBeforeSave: false });
    }

    // Step 12: Respond with the newly issued tokens and success message
    return new ApiResponse(
      StatusCodes.OK,
      {
        tokens: {
          accessToken,
          refreshToken,
        },
      },
      "Your session has been refreshed successfully. New tokens have been issued."
    ).send(res);
  }),

  // Controller to refresh user OTP
  refreshOTP: asyncHandler(async (req, res) => {
    // Step 1: Extract email from the request body
    const { email } = req.body;

    // Step 2: Find the user by email, selecting OTP-related fields
    const user = await User.findOne({ email }).select(
      "+otp +otpExpiration +otpAttempts +otpBlockedUntil"
    );

    // Step 3: Always respond with a generic message to prevent user enumeration
    if (!user) {
      return new ApiResponse(
        StatusCodes.OK,
        "If an account exists with this email, a new OTP has been sent for verification. Please check your inbox."
      ).send(res);
    }

    // Step 4: If the email is already verified, prevent further OTP generation
    if (user.isEmailVerified) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Email is already verified.");
    }

    // Step 5: Check if the user is temporarily blocked due to too many OTP attempts
    if (user.otpBlockedUntil && user.otpBlockedUntil > new Date()) {
      const remainingTime = Math.ceil(
        (user.otpBlockedUntil - Date.now()) / (60 * 1000) // Minutes remaining
      );
      throw new ApiError(
        StatusCodes.TOO_MANY_REQUESTS,
        `Too many OTP attempts. Please try again after ${remainingTime} minutes.`
      );
    }

    // Step 6: Generate a fresh OTP and set its expiration time (10 minutes)
    const otp = generateOTP();
    const otpExpiration = new Date(Date.now() + 10 * 60 * 1000);

    // Step 7: Reset OTP fields on the user document
    user.otp = otp;
    user.otpExpiration = otpExpiration;
    user.otpAttempts = 0;

    // Step 8: Save the updated user document without validation checks
    await user.save({ validateBeforeSave: false });

    // Step 9: Send the OTP email to the user
    try {
      await sendEmail({
        to: user.email,
        subject: "Verify Your Email",
        template: "emailVerification", // Assumes you're using templated emails
        context: {
          name: user.fullName,
          otp,
          expiresIn: "10 minutes",
        },
      });
    } catch (error) {
      // If sending email fails, clean up OTP fields for security
      user.otp = undefined;
      user.otpExpiration = undefined;
      await user.save({ validateBeforeSave: false });

      throw new ApiError(
        StatusCodes.INTERNAL_SERVER_ERROR,
        "Failed to send verification email."
      );
    }

    // Step 10: Respond with a success message (even if user was not found initially)
    return new ApiResponse(
      StatusCodes.OK,
      "If an account exists with this email, a new OTP has been sent for verification. Please check your inbox."
    ).send(res);
  }),

  // Controller to Refresh and regenerate a new QR Code
  refreshQrCode: asyncHandler(async (req, res) => {
    const { email } = req.body;

    // Validate request body
    if (!email) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Email is required.");
    }

    // Find user by email
    const user = await User.findOne({ email });

    // If user does not exist
    if (!user) {
      throw new ApiError(StatusCodes.NOT_FOUND, "User not found.");
    }

    // Generate a new TOTP secret
    const secret = speakeasy.generateSecret({
      name: `Blogger (${user.email})`,
    });

    // Update user's scanner secret
    user.scannerSecret = secret.base32;

    // Generate a new QR code image (Data URL format)
    const qrCodeDataUrl = await QRCode.toDataURL(secret.otpauth_url);
    user.qrCode = qrCodeDataUrl;

    // Generate new backup codes for recovery
    user.generateBackupCodes();

    // Save updated user information
    await user.save({ validateBeforeSave: false });

    // Respond with the newly generated QR code
    return new ApiResponse(
      StatusCodes.OK,
      { qrCode: qrCodeDataUrl },
      "Your 2FA QR Code has been refreshed successfully. Please scan it with your authenticator app."
    ).send(res);
  }),

  // Controller to retrieve active user sessions for the authenticated user.
  getActiveSessions: asyncHandler(async (req, res) => {
    // Retrieve the user ID from the authenticated user (assumed to be attached to req.user)
    const userId = req.user._id;

    // Find the user in the database and include sessions and refreshTokens fields in the query
    const user = await User.findById(userId).select("+sessions +refreshTokens");

    // If the user is not found, throw an error
    if (!user) {
      throw new ApiError(StatusCodes.NOT_FOUND, "User not found");
    }

    // Map through the user's sessions and structure the session data to include necessary details
    const sessions = user.sessions.map((session) => ({
      id: session._id, // Session ID
      ip: session.ip, // IP address associated with the session
      device: session.device, // Device associated with the session
      createdAt: session.createdAt, // Timestamp of when the session was created
      lastUsed: session.lastUsed, // Timestamp of the last time the session was used
      token: session.token === req.cookies?.accessToken, // Check if the session token matches the current access token in cookies
    }));

    // Return a success response with the list of active sessions
    return new ApiResponse(
      StatusCodes.OK, // HTTP status code for successful request
      { sessions }, // The data containing active sessions
      "Active sessions retrieved successfully" // Success message
    ).send(res); // Send the response to the client
  }),

  // Controller to revoke a specific user session based on the provided session ID.
  revokeSession: asyncHandler(async (req, res) => {
    // Destructure sessionId from the request body and get the user ID from the authenticated user.
    const { sessionId } = req.body;
    const userId = req.user._id;

    // If sessionId is not provided, throw a 'Session ID is required' error
    if (!sessionId) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Session ID is required");
    }

    // Find the user by their ID and include sessions and refreshTokens fields
    const user = await User.findById(userId).select("+sessions +refreshTokens");

    // If the user is not found, throw a 'User not found' error
    if (!user) {
      throw new ApiError(StatusCodes.NOT_FOUND, "User not found");
    }

    // Find the session to revoke from the user's sessions array using the provided sessionId
    const sessionToRevoke = user.sessions.id(sessionId);

    // If the session to revoke is not found, throw a 'Session not found' error
    if (!sessionToRevoke) {
      throw new ApiError(StatusCodes.NOT_FOUND, "Session not found");
    }

    // If the session to revoke is the current active session (based on the access token in cookies), throw an error
    if (sessionToRevoke.token === req.cookies?.accessToken) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Cannot revoke current session. Use logout instead."
      );
    }

    // Remove the associated refresh token of the session from the user's refreshTokens array
    user.refreshTokens = user.refreshTokens.filter(
      (rt) => rt.token !== sessionToRevoke.refreshToken
    );

    // Remove the session from the user's sessions array
    user.sessions.pull(sessionId);

    // Save the updated user document without validation before saving (as validation is handled separately)
    await user.save({ validateBeforeSave: false });

    // Return a successful response indicating the session has been revoked
    return new ApiResponse(StatusCodes.OK, "Session revoked successfully").send(
      res
    );
  }),

  // Controller to revoke all user sessions except the current session based on the access token in cookies.
  revokeAllSessions: asyncHandler(async (req, res) => {
    // Get the user ID from the authenticated user object.
    const userId = req.user._id;

    // Find the user by their ID, including sessions and refreshTokens fields.
    const user = await User.findById(userId).select("+sessions +refreshTokens");

    // If the user is not found, throw an error.
    if (!user) {
      throw new ApiError(StatusCodes.NOT_FOUND, "User not found");
    }

    // Get the current access token from the cookies.
    const currentToken = req.cookies?.accessToken;

    // Keep only the session that matches the current access token, effectively revoking all other sessions.
    user.sessions = user.sessions.filter((s) => s.token === currentToken);

    // Remove all refresh tokens that are associated with the revoked sessions.
    user.refreshTokens = user.refreshTokens.filter((rt) => {
      return user.sessions.some((s) => s.refreshToken === rt.token);
    });

    // Save the updated user document without validation (validation is handled separately).
    await user.save({ validateBeforeSave: false });

    // If there is no current token or the user has no active session left, clear the access and refresh token cookies.
    if (!currentToken || !user.sessions.length) {
      res.clearCookie("accessToken", OPTIONS);
      res.clearCookie("refreshToken", OPTIONS);
    }

    // Return a successful response indicating that all other sessions have been revoked.
    return new ApiResponse(
      StatusCodes.OK,
      "All other sessions revoked successfully"
    ).send(res);
  }),

  // Controller to update the last used time of the current session based on the access token in the cookies.
  currentSession: asyncHandler(async (req, res) => {
    // Retrieve the access token from the cookies
    const token = req.cookies?.accessToken;

    // If no token is found, throw an 'Unauthorized' error
    if (!token) {
      throw new ApiError(StatusCodes.UNAUTHORIZED, "Not authenticated");
    }

    // Find the user by searching for the session with the provided token
    const user = await User.findOne({
      "sessions.token": token, // Match the token in the sessions array
    }).select("+sessions"); // Include the 'sessions' field in the query result

    // If the user is not found, throw a 'User not found' error
    if (!user) {
      throw new ApiError(StatusCodes.NOT_FOUND, "User not found");
    }

    // Find the session that matches the current token
    const session = user.sessions.find((s) => s.token === token);

    // If the session is found, update its 'lastUsed' timestamp to the current time
    if (session) {
      session.lastUsed = new Date(); // Set the current time as the 'lastUsed' timestamp
      await user.save({ validateBeforeSave: false }); // Save the updated user document without validation
    }

    // Return a successful response indicating the session has been updated
    return new ApiResponse(StatusCodes.OK, "Session updated successfully").send(
      res
    );
  }),
};

export default AuthController;
