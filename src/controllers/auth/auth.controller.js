// External Packages
import mongoose from "mongoose";
import speakeasy from "speakeasy";
import QRCode from "qrcode";
import * as UAParser from "ua-parser-js";
import { StatusCodes } from "http-status-codes";
import axios from "axios";
import validator from "validator";

// Models
import User from "../../models/user.model.js";

// Configurations
import {
  uploadFileToCloudinary,
  deleteFileFromCloudinary,
} from "../../config/cloudinary.config.js";

// Constants
import {
  OPTIONS,
  GOOGLE_SECRET_KEY,
  OTP_EXPIRATION_TIME,
  MAX_OTP_ATTEMPTS,
  BLOCK_DURATION_MS,
} from "../../constants/constant.config.js";

// Middleware
import asyncHandler from "../../middleware/asyncHandler.middleware.js";

// Logger
import logger from "../../logger/winston.logger.js";

// Utilities
import ApiError from "../../utils/apiError.js";
import ApiResponse from "../../utils/apiResponse.js";
import generateOTP from "../../utils/otp.js";
import sendEmail from "../../utils/email.js";
import Api from "twilio/lib/rest/Api.js";

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
  // Controller: Register a new user
  registerUser: asyncHandler(async (req, res) => {
    // 1. Extract user details from the request body
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
      recaptchaToken,
    } = req.body;

    // 2. Sanitize input data to prevent malicious content
    const sanitizedEmail = validator.normalizeEmail(email?.toString().trim());
    const sanitizedUserName = validator.escape(userName?.toString().trim());
    const sanitizedFullName = validator.escape(fullName?.toString().trim());
    const sanitizedPhone = validator.escape(phone?.toString().trim());
    const sanitizedBio = bio ? validator.escape(bio) : "";
    const sanitizedGender = gender ? validator.escape(gender) : "";
    const sanitizedDateOfBirth = dateOfBirth
      ? validator.toDate(dateOfBirth)
      : null;

    // 3. Validate that required fields are provided
    if (
      [
        sanitizedEmail,
        sanitizedUserName,
        sanitizedFullName,
        sanitizedPhone,
        password,
      ].some((field) => !field?.toString().trim())
    ) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Full name, email, username, phone number, and password are required."
      );
    }

    // 4. Validate reCAPTCHA token presence
    if (!recaptchaToken) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "reCAPTCHA verification token is missing."
      );
    }

    // 5. Start a MongoDB session for atomic operations (transaction)
    const session = await User.startSession();
    session.startTransaction();

    let avatar; // To hold uploaded avatar info

    try {
      // 6. Check if avatar image is uploaded
      const avatarLocalPath = req?.file?.path;
      if (!avatarLocalPath) {
        throw new ApiError(
          StatusCodes.BAD_REQUEST,
          "Avatar image is required during registration."
        );
      }

      // 7. Upload avatar to Cloudinary
      avatar = await uploadFileToCloudinary(avatarLocalPath);
      if (!avatar?.secure_url || !avatar?.public_id) {
        if (avatar?.public_id) {
          await deleteFileFromCloudinary(avatar.public_id); // Cleanup partially uploaded file
        }
        throw new ApiError(
          StatusCodes.BAD_REQUEST,
          "Failed to upload and process profile image."
        );
      }

      // 8. Check if the user already exists based on email, username, or phone
      const existingUser = await User.findOne({
        $or: [
          { email: sanitizedEmail },
          { userName: sanitizedUserName },
          { phone: sanitizedPhone },
        ],
      });

      if (existingUser) {
        if (existingUser.email === sanitizedEmail) {
          throw new ApiError(StatusCodes.CONFLICT, "Email is already in use.");
        }
        if (existingUser.userName === sanitizedUserName) {
          throw new ApiError(
            StatusCodes.CONFLICT,
            "Username is already in use."
          );
        }
        if (existingUser.phone === sanitizedPhone) {
          throw new ApiError(
            StatusCodes.CONFLICT,
            "Phone number is already in use."
          );
        }
      }

      // 9. Generate OTP and expiration time
      const otp = generateOTP();
      const otpExpiration = OTP_EXPIRATION_TIME;

      // 10. Verify reCAPTCHA token with Google
      let recaptchaResponse;
      try {
        const { data } = await axios.post(
          `https://www.google.com/recaptcha/api/siteverify`,
          new URLSearchParams({
            secret: GOOGLE_SECRET_KEY,
            response: recaptchaToken,
          })
        );
        recaptchaResponse = data;
      } catch (recaptchaError) {
        logger.error(`reCAPTCHA API request failed: ${recaptchaError.message}`);
        throw new ApiError(
          StatusCodes.SERVICE_UNAVAILABLE,
          "reCAPTCHA verification service is currently unavailable. Please try again later."
        );
      }

      if (!recaptchaResponse?.success) {
        logger.warn(
          `reCAPTCHA verification failed: ${
            recaptchaResponse["error-codes"]?.join(", ") || "Unknown error"
          }`
        );
        throw new ApiError(
          StatusCodes.BAD_REQUEST,
          `reCAPTCHA verification failed: ${
            recaptchaResponse["error-codes"]?.join(", ") || "Invalid response"
          }`
        );
      }

      // 11. Create a new user instance
      const user = new User({
        fullName: sanitizedFullName,
        email: sanitizedEmail,
        userName: sanitizedUserName,
        password,
        phone: sanitizedPhone,
        bio: sanitizedBio,
        gender: sanitizedGender,
        dateOfBirth: sanitizedDateOfBirth,
        avatar: {
          publicId: avatar.public_id,
          url: avatar.secure_url,
        },
        socialLinks,
        otp,
        otpExpiration,
        ...req.body, // In case additional safe fields are included
      });

      // 12. Setup Two-Factor Authentication (2FA) secrets
      const secret = speakeasy.generateSecret({
        name: `Blogger (${user.email})`,
      });
      user.scannerSecret = secret.base32;
      user.qrCode = await QRCode.toDataURL(secret.otpauth_url);

      // 13. Generate backup codes for 2FA
      const backupCodes = await user.generateBackupCodes();

      // 14. Save the user into database (within session)
      await user.save({ session, validateBeforeSave: false });

      // 15. Send email verification with OTP
      try {
        await sendEmail({
          to: user.email,
          subject: "Verify Your Email",
          template: "emailVerification",
          context: {
            name: user.fullName,
            otp: otp,
            expiresIn: OTP_EXPIRATION_TIME,
          },
        });
      } catch (emailError) {
        // 16. On email failure, rollback user and avatar
        if (avatar?.public_id) {
          await deleteFileFromCloudinary(avatar.public_id);
        }
        await User.findByIdAndDelete(user._id, { session });
        throw new ApiError(
          StatusCodes.INTERNAL_SERVER_ERROR,
          "User created but failed to send verification email. Please contact support."
        );
      }

      // 17. Commit database transaction
      await session.commitTransaction();
      session.endSession();

      logger.info(`User registration successful: ${user.email}`);

      // 18. Send success response
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
          qrCode: user.qrCode,
        },
        "Registration successful! Please verify your email to activate your account."
      ).send(res);
    } catch (error) {
      // 19. Abort transaction if any error occurs
      await session.abortTransaction();
      session.endSession();
      logger.error(`User registration failed: ${error.message}`);

      // Cleanup avatar if uploaded
      if (avatar?.public_id) {
        await deleteFileFromCloudinary(avatar.public_id);
      }

      throw error; // Pass error to error handler
    }
  }),

  // Controller: Verify Email using OTP
  verifyEmail: asyncHandler(async (req, res) => {
    const { email, otp } = req.body;

    // 1. Validate required fields
    if (!email || !otp) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Both email and OTP are required for verification."
      );
    }

    // 2. Find the user by email with unexpired OTP and not yet verified
    const user = await User.findOne({
      email,
      otp: { $exists: true },
      otpExpiration: { $gt: Date.now() },
      isEmailVerified: false,
    }).select("+password +otp +otpExpiration +otpAttempts +otpBlockedUntil");

    if (!user) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Invalid or expired OTP. Please request a new one."
      );
    }

    // 3. Check if user is temporarily blocked due to too many failed attempts
    if (user.otpBlockedUntil && user.otpBlockedUntil > Date.now()) {
      throw new ApiError(
        StatusCodes.TOO_MANY_REQUESTS,
        "Too many failed attempts. Please try again later."
      );
    }

    // 4. Start a transaction session
    const session = await mongoose.startSession();
    let transactionActive = false;

    try {
      session.startTransaction();
      transactionActive = true;

      // 5. Compare submitted OTP with stored OTP
      const isValid = await user.compareOTP(otp);

      if (!isValid) {
        // 6. Increment failed attempts if OTP is invalid
        user.otpAttempts += 1;

        // 7. If max attempts exceeded, block further attempts temporarily
        if (user.otpAttempts >= MAX_OTP_ATTEMPTS) {
          user.otpBlockedUntil = new Date(Date.now() + BLOCK_DURATION_MS);
        }

        await user.save({ validateBeforeSave: false, session });

        // 8. Commit the session even if OTP was incorrect
        await session.commitTransaction();
        transactionActive = false;
        session.endSession();

        // 9. Handle response after too many wrong attempts
        if (user.otpBlockedUntil) {
          throw new ApiError(
            StatusCodes.TOO_MANY_REQUESTS,
            "Too many incorrect attempts. Please try again later."
          );
        } else {
          const attemptsLeft = MAX_OTP_ATTEMPTS - user.otpAttempts;
          throw new ApiError(
            StatusCodes.BAD_REQUEST,
            `Incorrect OTP. You have ${attemptsLeft} attempt(s) left.`
          );
        }
      }

      // 10. OTP is valid - Update user's verification status
      user.isEmailVerified = true;
      user.emailVerifiedAt = new Date();
      user.otp = undefined;
      user.otpExpiration = undefined;
      user.otpAttempts = 0;
      user.otpBlockedUntil = undefined;
      user.emailVerificationToken = undefined;
      user.emailVerificationTokenExpiration = undefined;

      // 11. Record security log
      user.securityLogs.push({
        action: "email_verified",
        ip: req.ip,
        userAgent: req.headers["user-agent"],
      });

      // 12. Save updated user
      await user.save({ validateBeforeSave: false, session });

      // 13. Commit and end the transaction
      await session.commitTransaction();
      transactionActive = false;
      session.endSession();

      // 14. Send success response
      return new ApiResponse(
        StatusCodes.OK,
        { isEmailVerified: true },
        "Your email has been successfully verified."
      ).send(res);
    } catch (error) {
      // 15. Rollback transaction if error occurred
      if (transactionActive) {
        try {
          await session.abortTransaction();
        } catch (abortError) {
          console.error("Abort transaction failed:", abortError.message);
        }
      }
      session.endSession();

      // 16. Log error details
      logger.error("Error during email verification session:", {
        error: error.message,
        email: user?.email,
        userId: user?._id,
        ip: req.ip,
        userAgent: req.headers["user-agent"],
      });

      // 17. Re-throw the error appropriately
      if (error instanceof ApiError) {
        throw error;
      }

      throw new ApiError(
        StatusCodes.INTERNAL_SERVER_ERROR,
        "Something went wrong during verification. Please try again."
      );
    }
  }),

  // Controller to log in a user
  loginUser: asyncHandler(async (req, res) => {
    // Destructure necessary fields from the request body
    const { email, userName, phone, password } = req.body;

    // Step 1: Validate input - require password and at least one identifier (email, username, or phone)
    if (!password || (!email && !userName && !phone)) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Password and at least one of email, username, or phone number must be provided."
      );
    }

    // Step 2: Find user by email, username, or phone (case-insensitive)
    const user = await User.findOne({
      $or: [{ email }, { userName }, { phone }],
    }).select(
      "+password +isActive +isSuspended +isEmailVerified +accountLockTime +failedLoginAttempts +lastLoginAttempt +twoFactorEnabled +scannerSecret +twoFactorBackupCodes +sessions"
    );

    // Step 3: Handle user not found - add delay to mitigate user enumeration attacks
    if (!user) {
      await new Promise((resolve) => setTimeout(resolve, 500)); // Adding delay
      throw new ApiError(StatusCodes.UNAUTHORIZED, "Invalid credentials.");
    }

    // Step 4: Validate the provided password (compare hashed password with input)
    const isValid = await user.comparePassword(password);

    if (!isValid) {
      // Step 4a: Register failed attempt and add delay response to mitigate brute force
      await user.registerFailedLogin(); // Increment failed login attempts
      await new Promise((resolve) => setTimeout(resolve, 500)); // Adding delay
      throw new ApiError(StatusCodes.UNAUTHORIZED, "Invalid credentials.");
    }

    // Step 5: Check account status flags (active, suspended, verified)
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

    // Step 7: Parse device/browser info for session tracking (fingerprint to track sessions)
    const Fingerprint = deviceFingerprint(req);

    // Step 8: Generate access and refresh tokens
    const { accessToken, refreshToken } = await generateTokens(
      user._id,
      req.ip,
      req.headers["user-agent"],
      Fingerprint,
      req
    );

    // Step 9: Reset login attempts and log new session in the database
    await User.findByIdAndUpdate(
      user._id,
      {
        $set: {
          loginAttempts: 0, // Reset failed login attempts
          lockUntil: undefined, // Unlock the account if previously locked
          lastLogin: {
            // Log the new login details
            ip: req.ip,
            device: req.headers["user-agent"],
            timestamp: new Date(),
          },
        },
        $push: {
          sessions: {
            // Push session details to the `sessions` array
            ipAddress: req.ip,
            userAgent: req.headers["user-agent"],
            deviceFingerprint: Fingerprint, // Store device fingerprint
            createdAt: new Date(), // Store timestamp of the session
          },
        },
      },
      { validateBeforeSave: false, new: true } // Avoid validation before saving and return the updated user document
    );

    // Step 10: Set secure, HTTP-only cookies for the tokens (to maintain the user session)
    res
      .cookie("accessToken", accessToken, OPTIONS) // Set access token cookie
      .cookie("refreshToken", refreshToken, OPTIONS); // Set refresh token cookie

    // Step 11: Send successful login response with minimal safe user info (to avoid overexposure)
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
          refreshToken, // Include the generated tokens
        },
      },
      "Login successful. Welcome back!" // Success message
    ).send(res);
  }),

  // Controller for QR Code-based Login for User
  loginQrBaseUser: asyncHandler(async (req, res) => {
    // Step 1: Extract email and token from the request body
    const { email, token } = req.body;

    // Step 2: Validate required input fields
    if (!email || !token) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Email and Token are required to log in."
      );
    }

    // Step 3: Fetch user by email, selecting sensitive 2FA fields
    const user = await User.findOne({ email }).select(
      "+scannerSecret +otp +otpExpiration"
    );

    // Step 4: Ensure user exists and has set up 2FA scanner
    if (!user || !user.scannerSecret) {
      throw new ApiError(
        StatusCodes.NOT_FOUND,
        "User not found or OTP is not set up. Please enable two-factor authentication first."
      );
    }

    // Step 5: Verify the provided token against the user's scanner secret
    const isVerified = speakeasy.totp.verify({
      secret: user.scannerSecret,
      encoding: "base32",
      token,
      window: 1, // Allow a 1-step time window before/after
    });

    // Step 6: If token verification fails, throw an unauthorized error
    if (!isVerified) {
      throw new ApiError(StatusCodes.UNAUTHORIZED, "Invalid or expired token.");
    }

    // Step 7: If token verification succeeds, proceed with login
    try {
      // Step 7.1: Reset login-related fields (loginAttempts, lockout, etc.)
      user.resetLoginState(req.ip, req.headers["user-agent"]);

      // Step 7.2: Save updated user state to the database
      await user.save({ validateBeforeSave: false });

      // Step 7.3: Generate device fingerprint for session tracking
      const Fingerprint = deviceFingerprint(req);

      // Step 7.4: Issue new access and refresh tokens for the user
      const { accessToken, refreshToken } = await generateTokens(
        user._id,
        req.ip,
        req.headers["user-agent"],
        Fingerprint,
        req
      );

      // Step 8: Set the generated tokens into secure HTTP-only cookies
      res.cookie("accessToken", accessToken, OPTIONS);
      res.cookie("refreshToken", refreshToken, OPTIONS);

      // Step 9: Respond with user profile details and new tokens
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
      // Step 10: Handle unexpected errors during login process
      console.error("Login error:", error);
      throw new ApiError(StatusCodes.INTERNAL_SERVER_ERROR, "Failed to login.");
    }
  }),

  // Controller for Forgot Password functionality for User
  forgotPassword: asyncHandler(async (req, res) => {
    const { email } = req.body;

    // Step 1: Validate that email is provided in the request body
    // Check if email is provided; if not, throw an error
    if (!email) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Email is required.");
    }

    // Step 2: Start a Mongoose session for transaction handling
    // Start a session to ensure that all database changes are executed in a transaction
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      // Step 3: Find the user by email, and select necessary fields (OTP and OTP expiration)
      // Look for a user with the provided email and include OTP-related fields to update them later
      const user = await User.findOne({ email })
        .select("+otp +otpExpiration") // Ensure the OTP fields are selected
        .session(session); // Link the session to the query to ensure transaction consistency

      // Step 4: Handle case where no user is found with the given email
      // If user is not found, throw a 'Not Found' error
      if (!user) {
        throw new ApiError(StatusCodes.NOT_FOUND, "User not found.");
      }

      // Step 5: Generate password reset token and OTP for the user
      // Create a new password reset token and generate an OTP (One-Time Password)
      const resetToken = user.generatePasswordResetToken(); // Generate the reset token
      const otp = generateOTP(); // Call function to generate the OTP
      const otpExpiration = OTP_EXPIRATION_TIME; // Set OTP expiration to 15 minutes from now

      // Step 6: Assign the generated OTP and reset token to the user
      // Save the generated OTP, OTP expiration, and reset token along with its expiration
      user.otp = otp;
      user.otpExpiration = otpExpiration;
      user.passwordResetToken = resetToken;
      user.passwordResetTokenExpiration = OTP_EXPIRATION_TIME; // Expiration time for reset token (15 minutes)

      // Step 7: Save the updated user document within the session
      // Save the updated user data (OTP, reset token, etc.) in the session
      await user.save({ validateBeforeSave: false, session });

      // Step 8: Generate the password reset URL with the reset token
      // Construct the password reset URL that the user will use to reset their password
      const resetUrl = `http://localhost:3000/api/v1/auth/reset-password/${resetToken}`;

      // Step 9: Send the password reset email to the user with OTP and reset URL
      // Send an email to the user containing the OTP and the reset URL
      await sendEmail({
        to: user.email, // User's email to send the reset information
        subject: "Password Reset Request", // Email subject
        template: "passwordReset", // Use a predefined email template
        context: {
          name: user.fullName, // Include the user's full name in the email template
          otp: otp, // Include the generated OTP
          resetUrl: resetUrl, // Include the password reset URL
          expiresIn: OTP_EXPIRATION_TIME, // Include the expiration time for the OTP and link
        },
        session, // Optionally track email sending as part of the transaction
      });

      // Step 10: Commit the transaction to apply all changes
      // If all operations (user update, email sending) are successful, commit the transaction to save the changes
      await session.commitTransaction();

      // Step 11: Send a successful response back to the client
      // Return a success message and the reset URL to the user
      return new ApiResponse(
        StatusCodes.OK,
        { resetUrl }, // Send the reset URL in the response
        "OTP and Password Reset link sent to your email."
      ).send(res);
    } catch (error) {
      // Step 12: Handle errors and abort the transaction if any operation fails
      // If an error occurs at any point, abort the transaction to ensure no changes are persisted
      await session.abortTransaction();
      throw error; // Rethrow the error for further handling by the global error handler
    } finally {
      // Step 13: End the session after the transaction is complete (whether successful or not)
      // Clean up and end the Mongoose session to release resources
      session.endSession();
    }
  }),

  // Controller for Reset Password Using OTP functionality for User
  resetPasswordWithOtp: asyncHandler(async (req, res) => {
    // Extract required fields from request body
    const { email, otp, newPassword, confirmPassword } = req.body;

    // Step 1: Check if all fields are provided
    if ([email, otp, newPassword, confirmPassword].some((field) => !field)) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Please provide all the required fields: email, OTP, new password, and confirm password."
      );
    }

    // Step 2: Check if newPassword and confirmPassword match
    if (newPassword !== confirmPassword) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Passwords do not match.");
    }

    // Step 3: Start a Mongoose session for transaction handling
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      // Step 4: Find user by email and select OTP-related fields explicitly
      const user = await User.findOne({ email })
        .select("+otp +otpExpiration")
        .session(session); // Use session here

      // Step 5: If user not found, throw an error
      if (!user) {
        throw new ApiError(StatusCodes.NOT_FOUND, "User not found.");
      }

      // Step 6: Validate provided OTP
      const isValid = await user.compareOTP(otp);

      // Step 7: If OTP is invalid or expired, throw an error
      if (!isValid) {
        throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid or expired OTP.");
      }

      // Step 8: OTP is valid: reset the password and clear OTP-related fields
      user.password = newPassword; // Update password
      user.otp = undefined; // Clear OTP field
      user.otpExpiration = undefined; // Clear OTP expiration field
      user.passwordResetToken = undefined; // Clear the password reset token field

      // Step 9: Save updated user details within the session
      await user.save({ validateBeforeSave: false }, { session });

      // Step 10: Commit the transaction if everything is successful
      await session.commitTransaction();

      // Step 11: Send success response
      return new ApiResponse(
        StatusCodes.OK,
        "Password reset successfully via OTP."
      ).send(res);
    } catch (error) {
      // Step 12: If any error occurs, abort the transaction and throw the error
      await session.abortTransaction();
      throw error; // Rethrow the error for global error handling
    } finally {
      // Step 13: End the session after the transaction is complete (whether successful or not)
      session.endSession();
    }
  }),

  // Controller to reset password using reset token
  resetPasswordWithToken: asyncHandler(async (req, res) => {
    // Extract token from URL parameters
    const { token } = req.params;
    // Extract required fields from request body
    const { email, newPassword, confirmPassword } = req.body;

    // Step 1: Validate required inputs
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

    // Step 2: Ensure new password and confirm password match
    if (newPassword !== confirmPassword) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Passwords do not match.");
    }

    // Step 3: Start a Mongoose session for transaction handling
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      // Step 4: Find user by email, token, and ensure token is not expired
      const user = await User.findOne({
        email,
        passwordResetToken: token,
        passwordResetTokenExpiration: { $gt: new Date() }, // Token should not be expired
      })
        .select(
          "+otp +otpExpiration +passwordResetToken +passwordResetTokenExpiration" // Select necessary fields
        )
        .session(session); // Use session for transaction handling

      // Step 5: If user not found or token invalid/expired, throw error
      if (!user) {
        throw new ApiError(
          StatusCodes.BAD_REQUEST,
          "Invalid or expired reset token."
        );
      }

      // Step 6: Update user's password and clear password reset fields
      user.password = newPassword; // Set new password
      user.passwordResetToken = undefined; // Clear reset token
      user.passwordResetTokenExpiration = undefined; // Clear reset token expiration
      user.otp = undefined; // Clear OTP field
      user.otpExpiration = undefined; // Clear OTP expiration

      // Step 7: Save updated user document within the session
      await user.save({ validateBeforeSave: false }, { session });

      // Step 8: Commit the transaction if everything is successful
      await session.commitTransaction();

      // Step 9: Send success response
      return new ApiResponse(
        StatusCodes.OK,
        "Password reset successfully via link."
      ).send(res);
    } catch (error) {
      // Step 10: If any error occurs, abort the transaction and throw the error
      await session.abortTransaction();
      throw error; // Rethrow the error for global error handling
    } finally {
      // Step 11: End the session after the transaction is complete (whether successful or not)
      session.endSession();
    }
  }),

  // Controller to log out a user
  logoutUser: asyncHandler(async (req, res) => {
    const refreshToken = req?.cookies?.refreshToken;
    const accessToken = req?.cookies?.accessToken;

    // Step 1: Validate that a refresh token is provided
    if (!refreshToken) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Refresh token required");
    }

    // Step 2: Start a Mongoose session for transaction handling
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      // Step 3: Authenticate user using the refresh token
      const user = await User.authenticateToken(refreshToken);

      // Step 4: Handle invalid or expired refresh token
      if (!user) {
        throw new ApiError(StatusCodes.UNAUTHORIZED, "Invalid refresh token.");
      }

      // Step 5: Remove the used refresh token from user's stored tokens
      user.refreshTokens = user.refreshTokens.filter(
        (tokenObj) => tokenObj.token !== refreshToken
      );

      // Step 6: Also remove the matching session if access token is available
      if (accessToken) {
        user.sessions = user.sessions.filter(
          (session) => session.token !== accessToken
        );
      }

      // Step 7: Invalidate two-factor authentication status
      user.is2faVerified = false;

      // Step 8: Save the updated user document within the session
      await user.save({ validateBeforeSave: false, session });

      // Step 9: Commit the transaction if everything is successful
      await session.commitTransaction();

      // Step 10: Clear authentication cookies
      res.clearCookie("refreshToken", OPTIONS);
      res.clearCookie("accessToken", OPTIONS);

      // Step 11: Send logout success response
      return new ApiResponse(StatusCodes.OK, "Logged out successfully").send(
        res
      );
    } catch (error) {
      // Step 12: If any error occurs, abort the transaction and throw the error
      await session.abortTransaction();
      throw error;
    } finally {
      // Step 13: End the session after the transaction is complete (whether successful or not)
      session.endSession();
    }
  }),

  // Controller to Refresh Token for User
  refreshToken: asyncHandler(async (req, res) => {
    const session = await mongoose.startSession(); // Start a MongoDB session

    try {
      // Step 1: Extract the refresh token from cookies
      const incomingRefreshToken = req.cookies?.refreshToken;

      if (!incomingRefreshToken) {
        throw new ApiError(StatusCodes.UNAUTHORIZED, "Unauthorized request");
      }

      // Step 2: Verify the refresh token and find the user
      const user = await User.authenticateToken(incomingRefreshToken);

      if (!user) {
        throw new ApiError(StatusCodes.UNAUTHORIZED, "Invalid refresh token");
      }

      // Step 3: Check if the refresh token exists inside user's refreshTokens array
      const tokenEntry = user.refreshTokens.find(
        (t) => t.token === incomingRefreshToken
      );

      if (!tokenEntry) {
        throw new ApiError(StatusCodes.UNAUTHORIZED, "Refresh token not found");
      }

      // Step 4: Check if the refresh token has expired
      if (tokenEntry.expiresAt < new Date()) {
        throw new ApiError(StatusCodes.UNAUTHORIZED, "Refresh token expired");
      }

      // Step 5: Parse device/browser information for session tracking
      const fingerprint = deviceFingerprint(req);

      // Step 6: Generate new access and refresh tokens
      const { accessToken, refreshToken } = await generateTokens(
        user._id,
        req.ip,
        req.headers["user-agent"],
        fingerprint,
        req
      );

      // Start transaction
      session.startTransaction();

      // Step 7: Remove the old refresh token and add the new one
      user.refreshTokens = user.refreshTokens.filter(
        (t) => t.token !== incomingRefreshToken
      );
      user.refreshTokens.push({
        token: refreshToken,
        createdAt: new Date(),
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days validity
      });

      // Step 8: Reset login attempts, log session details, and save the user
      await User.findByIdAndUpdate(
        user._id,
        {
          $set: {
            loginAttempts: 0, // Reset failed login attempts
            lockUntil: undefined, // Unlock account if previously locked
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
              deviceFingerprint: fingerprint,
              createdAt: new Date(),
            },
          },
          refreshTokens: user.refreshTokens, // Updated refreshTokens
        },
        { session, validateBeforeSave: false, new: true }
      );

      // Commit transaction
      await session.commitTransaction();
      session.endSession(); // End session

      // Step 9: Set secure HTTP-only cookies for tokens
      res
        .cookie("accessToken", accessToken, OPTIONS) // Secure access token cookie
        .cookie("refreshToken", refreshToken, OPTIONS); // Secure refresh token cookie

      // Step 10: Send success response
      return new ApiResponse(
        StatusCodes.OK,
        {
          accessToken,
          refreshToken,
        },
        "Tokens refreshed successfully."
      ).send(res);
    } catch (error) {
      await session.abortTransaction(); // If any error occurs, abort transaction
      session.endSession();
      throw error; // Propagate error
    }
  }),

  // Controller to refresh OTP
  refreshOTP: asyncHandler(async (req, res) => {
    // Step 1: Extract email from the request body
    const { email } = req.body;

    // Start a Mongoose session for transaction handling
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      // Step 2: Find the user by email, selecting OTP-related fields
      const user = await User.findOne({ email })
        .select("+otp +otpExpiration +otpAttempts +otpBlockedUntil")
        .session(session); // Include the session here

      // Step 3: Always respond with a generic message to prevent user enumeration
      if (!user) {
        await session.commitTransaction(); // Commit if user not found
        return new ApiResponse(
          StatusCodes.OK,
          "If an account exists with this email, a new OTP has been sent for verification. Please check your inbox."
        ).send(res);
      }

      // Step 4: If the email is already verified, prevent further OTP generation
      if (user.isEmailVerified) {
        await session.commitTransaction(); // Commit if email is verified
        throw new ApiError(
          StatusCodes.BAD_REQUEST,
          "Email is already verified."
        );
      }

      // Step 5: Check if the user is temporarily blocked due to too many OTP attempts
      if (user.otpBlockedUntil && user.otpBlockedUntil > new Date()) {
        const remainingTime = Math.ceil(
          (user.otpBlockedUntil - Date.now()) / (60 * 1000) // Minutes remaining
        );
        await session.commitTransaction(); // Commit if blocked
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
      await user.save({ validateBeforeSave: false, session });

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
        await user.save({ validateBeforeSave: false, session });

        // Rollback the transaction
        await session.abortTransaction();

        throw new ApiError(
          StatusCodes.INTERNAL_SERVER_ERROR,
          "Failed to send verification email."
        );
      }

      // Step 10: Commit the transaction if all steps are successful
      await session.commitTransaction();

      // Step 11: Respond with a success message (even if user was not found initially)
      return new ApiResponse(
        StatusCodes.OK,
        "If an account exists with this email, a new OTP has been sent for verification. Please check your inbox."
      ).send(res);
    } catch (error) {
      // If an error occurs, abort the transaction
      await session.abortTransaction();
      throw error;
    } finally {
      // End the session after the transaction is complete (whether successful or not)
      session.endSession();
    }
  }),

  // Controller to refresh OTP
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
