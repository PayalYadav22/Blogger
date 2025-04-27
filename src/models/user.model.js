/**
 * @copyright 2025 Payal Yadav
 * @license Apache-2.0
 */

// ==============================
// Imports
// ==============================

import mongoose from "mongoose";
import bcrypt from "bcrypt";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import validator from "validator";
import softDeletePlugin from "../plugins/softDelete.plugin.js";
import sanitize from "mongoose-sanitize";
import leanVirtuals from "mongoose-lean-virtuals";
import leanGetters from "mongoose-lean-getters";
import {
  SALT_ROUND,
  JWT_ACCESS_SECRET,
  JWT_ACCESS_SECRET_EXPIRESIN,
  JWT_REFRESH_SECRET,
  JWT_REFRESH_SECRET_EXPIRESIN,
} from "../constants/constant.config.js";
import ApiError from "../utils/apiError.js";
import { StatusCodes } from "http-status-codes";

// ==============================
// Schema Definition
// ==============================

const UserSchema = new mongoose.Schema(
  {
    // ------------------------------
    // Basic account info
    // ------------------------------
    email: {
      type: String,
      required: [true, "Email is required"],
      unique: true,
      trim: true,
      lowercase: true,
      validate: {
        validator: (v) => validator.isEmail(v),
        message: "Invalid email address",
      },
    },
    phone: {
      type: String,
      required: [true, "Phone No is required"],
      unique: true,
      trim: true,
      validate: {
        validator: (v) => validator.isMobilePhone(v, "any"),
        message: "Invalid phone number",
      },
    },
    password: {
      type: String,
      required: [true, "Password is required"],
      select: false,
      validate: {
        validator: function (v) {
          return (
            !this.isModified("password") ||
            validator.isStrongPassword(v, {
              minLength: 8,
              minLowercase: 1,
              minUppercase: 1,
              minNumbers: 1,
              minSymbols: 1,
            })
          );
        },
        message:
          "Password must be at least 8 characters with 1 lowercase, 1 uppercase, 1 number, and 1 symbol",
      },
    },
    passwordChangedAt: {
      type: Date,
    },

    // ------------------------------
    // Security fields
    // ------------------------------
    passwordHistory: {
      type: [String],
      select: false,
      default: [],
      validate: {
        validator: function (arr) {
          return arr.length <= 5;
        },
        message: "Password history cannot exceed 5 entries.",
      },
    },
    otp: { type: String, select: false },
    otpExpiration: { type: Date, select: false },

    // ------------------------------
    // Session/token handling
    // ------------------------------
    tokens: [
      {
        token: {
          type: String,
          required: [true, "Access token is required"],
        },
        createdAt: { type: Date, default: Date.now },
      },
    ],
    refreshTokens: [
      {
        token: {
          type: String,
          required: [true, "Refresh token is required"],
        },
        createdAt: { type: Date, default: Date.now },
        expiresAt: {
          type: Date,
          required: [true, "Expiration date for refresh token is required"],
        },
      },
    ],
    sessions: [
      {
        token: { type: String, required: true },
        refreshToken: { type: String, required: true },
        ip: { type: String },
        device: { type: String },
        createdAt: { type: Date, default: Date.now },
        lastUsed: { type: Date, default: Date.now },
        deviceFingerprint: {
          browser: { type: String },
          os: { type: String },
          device: { type: String },
          platform: { type: String },
        },
      },
    ],
    // ------------------------------
    // Profile fields
    // ------------------------------
    fullName: {
      type: String,
      required: [true, "Full name is required"],
      minlength: [3, "Full name must be at least 3 characters"],
      maxlength: [50, "Full name must be less than 50 characters"],
    },
    userName: {
      type: String,
      required: [true, "userName is required"],
      minlength: [3, "userName must be at least 3 characters"],
      maxlength: [50, "userName must be less than 50 characters"],
    },
    bio: { type: String, default: "" },
    dateOfBirth: {
      type: Date,
      validate: {
        validator: (v) => {
          if (!v) return true;
          const parsedDate = new Date(v);
          return parsedDate <= new Date();
        },
        message: "Date of birth cannot be in the future",
      },
    },
    gender: {
      type: String,
      enum: ["male", "female", "trans"],
    },
    avatar: {
      url: {
        type: String,
        validate: {
          validator: (v) => !v || /^https?:\/\/\S+/.test(v),
          message: "Invalid avatar URL",
        },
      },
      publicId: { type: String },
    },
    socialLinks: {
      website: {
        type: String,
        validate: {
          validator: (v) => !v || /^https?:\/\/\S+/.test(v),
          message: "Invalid website URL",
        },
      },
      twitter: {
        type: String,
        validate: {
          validator: (v) =>
            !v || /^https?:\/\/(www\.)?twitter\.com\/[A-Za-z0-9_]+/.test(v),
          message: "Invalid Twitter URL",
        },
      },
      github: {
        type: String,
        validate: {
          validator: (v) =>
            !v || /^https?:\/\/(www\.)?github\.com\/[A-Za-z0-9-]+/.test(v),
          message: "Invalid GitHub URL",
        },
      },
    },
    location: {
      type: String,
      maxlength: [100, "Location cannot exceed 100 characters"],
    },

    // ------------------------------
    // Role and permissions
    // ------------------------------
    role: {
      type: String,
      enum: [
        "admin",
        "editor",
        "writer",
        "viewer",
        "moderator",
        "contributor",
        "subscriber",
      ],
      default: "viewer",
    },
    postLimit: { type: Number, default: 10 },

    // ------------------------------
    // Account status flags
    // ------------------------------
    isActive: { type: Boolean, default: true },
    isSuspended: { type: Boolean, default: false },
    deactivatedAt: { type: Date, select: false },
    deactivatedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" },

    // ------------------------------
    // Content activity tracking
    // ------------------------------
    postCount: { type: Number, default: 0 },
    views: { type: Number, default: 0 },
    totalViews: { type: Number, default: 0 },
    popularityScore: { type: Number, default: 0 },
    lastTrendingUpdate: { type: Date },
    lastActivityAt: {
      type: Date,
      default: Date.now,
    },

    // ------------------------------
    // Subscription fields
    // ------------------------------
    isPremium: { type: Boolean, default: false, select: false },
    subscriptionTier: {
      type: String,
      enum: ["free", "basic", "premium"],
      default: "free",
    },

    // ------------------------------
    // Notification preferences
    // ------------------------------
    notificationSettings: {
      emailOnMention: { type: Boolean, default: true },
      emailOnFollow: { type: Boolean, default: true },
    },

    // ------------------------------
    // Optional user details
    // ------------------------------
    backupEmail: {
      type: String,
      validate: {
        validator: (v) => !v || validator.isEmail(v),
        message: "Invalid backup email address",
      },
    },
    authorBio: {
      type: String,
      default: "",
      maxlength: [500, "Author bio must not exceed 500 characters"],
    },
    specialization: { type: String, default: "" },

    // ------------------------------
    // Account verification
    // ------------------------------
    isEmailVerified: { type: Boolean, default: false },
    emailVerificationToken: { type: String, select: false },
    emailVerificationTokenExpiration: { type: Date, select: false },
    emailVerifiedAt: { type: Date, select: false },

    // ------------------------------
    // Login and reset tracking
    // ------------------------------
    failedLoginAttempts: { type: Number, default: 0 },
    loginAttempts: { type: Number, default: 0 },
    lockUntil: { type: Date },
    lastLoginAttempt: { type: Date, select: false },
    accountLockTime: { type: Date, select: false },
    passwordResetToken: { type: String, select: false },
    passwordResetTokenExpiration: { type: Date, select: false },
    failedResetAttempts: { type: Number, default: 0 },
    lastPasswordResetRequest: { type: Date },
    passwordResetCooldown: { type: Number, default: 10 * 60 * 1000 },
    lastPasswordChange: { type: Date, default: Date.now },

    // ------------------------------
    // User privacy settings
    // ------------------------------
    profilePrivacy: {
      type: String,
      enum: ["public", "private", "friends"],
      default: "public",
    },

    // ------------------------------
    // Miscellaneous tracking
    // ------------------------------
    lastLogin: {
      ip: String,
      device: String,
      timestamp: Date,
    },
    securityLogs: [
      {
        action: {
          type: String,
          required: true,
        },
        timestamp: {
          type: Date,
          default: Date.now,
        },
        ip: {
          type: String,
        },
      },
    ],
    passwordResetHistory: [
      {
        ip: String,
        timestamp: Date,
      },
    ],
    otpAttempts: { type: Number, default: 0 },
    otpBlockedUntil: { type: Date, select: false },
    blockedUsers: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
    lastSensitiveOperations: {
      type: Map,
      of: Date,
      default: {},
      select: false,
    },

    // ------------------------------
    // QR Code
    // ------------------------------
    qrCode: { type: String },
    scannerSecret: {
      type: String,
    },
    is2faVerified: {
      type: Boolean,
      default: false,
    },

    backupCodes: {
      type: [
        {
          code: { type: String, select: false },
          used: { type: Boolean, default: false },
          createdAt: { type: Date, default: Date.now },
        },
      ],
      select: false,
      default: [],
    },
    twoFactorFallback: {
      type: String,
      enum: ["sms", "email"],
      default: "email",
    },

    // ------------------------------
    // Social/follow data
    // ------------------------------
    followersCount: { type: Number, default: 0 },
    followingCount: { type: Number, default: 0 },
    posts: [{ type: mongoose.Schema.Types.ObjectId, ref: "Post", default: [] }],
    comments: [
      { type: mongoose.Schema.Types.ObjectId, ref: "Comment", default: [] },
    ],
    likes: [{ type: mongoose.Schema.Types.ObjectId, ref: "Post", default: [] }],
    bookmarks: [
      { type: mongoose.Schema.Types.ObjectId, ref: "Post", default: [] },
    ],

    // ------------------------------
    // Legacy account migration
    // ------------------------------
    isLegacyAccount: { type: Boolean, default: false },
    migrationStatus: String,

    // ------------------------------
    // Localization
    // ------------------------------
    languagePreference: {
      type: String,
      default: "en",
      enum: ["en", "es", "fr", "de", "it"],
    },
    timezone: {
      type: String,
      default: "UTC",
      enum: ["UTC", "GMT", "PST", "EST", "CET"],
    },
  },
  { timestamps: true }
);

// ==============================
// Middleware
// ==============================
UserSchema.pre("save", async function (next) {
  try {
    const saltRounds = SALT_ROUND;

    if (this.isModified("password") && this.password) {
      if (!this.password) {
        return next(new Error("Password is required"));
      }

      if (this.passwordHistory?.length > 0) {
        const isReused = await Promise.all(
          this.passwordHistory.map(async (oldHash) => {
            return await bcrypt.compare(this.password, oldHash);
          })
        ).then((results) => results.includes(true));

        if (isReused) {
          return next(
            new ApiError(
              StatusCodes.BAD_REQUEST,
              "You cannot reuse an old password."
            )
          );
        }
      }

      const salt = await bcrypt.genSalt(saltRounds);
      const hash = await bcrypt.hash(this.password, salt);

      // Save current password hash into password history
      if (this.isModified("passwordHistory")) {
        this.passwordHistory.unshift(hash);
      } else {
        this.passwordHistory = [hash, ...(this.passwordHistory || [])];
      }

      // Keep only last 5 passwords
      this.passwordHistory = this.passwordHistory.slice(0, 5);

      // Save new hashed password
      this.password = hash;

      // Update lastPasswordChange timestamp
      this.lastPasswordChange = new Date();
    }
    if (this.isModified("otp") && this.otp) {
      const salt = await bcrypt.genSalt(saltRounds);
      const hash = await bcrypt.hash(this.otp, salt);
      this.otp = hash;
    }

    next();
  } catch (error) {
    next(error);
  }
});

// ==============================
// Instance Methods
// ==============================

// Password & OTP Comparision
UserSchema.methods.comparePassword = async function (password) {
  return password && this.password
    ? bcrypt.compare(password, this.password)
    : false;
};

UserSchema.methods.compareOTP = async function (otp) {
  return otp && this.otp ? bcrypt.compare(otp, this.otp) : false;
};

// Generate JWT access and refresh tokens
UserSchema.methods.generateAccessToken = async function () {
  const now = new Date();

  const accessToken = jwt.sign(
    {
      _id: this._id,
      email: this.email,
      phone: this.phone,
      userName: this.userName,
      role: this.role,
      fullName: this.fullName,
      has2FA: !!this.scannerSecret,
      is2faVerified: this.is2faVerified,
    },
    JWT_ACCESS_SECRET,
    { expiresIn: JWT_ACCESS_SECRET_EXPIRESIN }
  );

  this.tokens.push({
    token: accessToken,
    createdAt: now,
  });

  return accessToken;
};

UserSchema.methods.generateRefreshToken = async function (req) {
  const now = new Date();
  const refreshExpiry = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);

  const refreshToken = jwt.sign(
    {
      _id: this._id,
      jti: crypto.randomBytes(16).toString("hex"),
      email: this.email,
      phone: this.phone,
      userName: this.userName,
      role: this.role,
      fullName: this.fullName,
      has2FA: !!this.scannerSecret,
      userAgent: req.headers["user-agent"],
      ipAddress: req.ip,
      issuedAt: now.getTime(),
    },
    JWT_REFRESH_SECRET,
    { expiresIn: JWT_REFRESH_SECRET_EXPIRESIN }
  );

  // Add the refresh token to the refreshTokens array
  this.refreshTokens.push({
    token: refreshToken,
    createdAt: now,
    expiresAt: refreshExpiry,
  });

  return refreshToken;
};

// Reset Login Attempts
UserSchema.methods.resetLoginState = function (ip, userAgent) {
  this.lastLogin = {
    ip: ip,
    device: userAgent,
    timestamp: new Date(),
  };
};

// Check if the user can attempt login (not locked)
UserSchema.methods.canAttemptLogin = async function () {
  return !(this.accountLockTime && this.accountLockTime > Date.now());
};

// Register a failed login and possibly lock the account
UserSchema.methods.registerFailedLogin = async function () {
  this.failedLoginAttempts += 1;
  this.lastLoginAttempt = new Date();
  if (this.failedLoginAttempts >= 5) {
    this.accountLockTime = new Date(Date.now() + 15 * 60 * 1000);
  }
  await this.save();
};

UserSchema.methods.checkPasswordReuse = async function (newPassword) {
  for (const oldPassword of this.passwordHistory) {
    if (await bcrypt.compare(newPassword, oldPassword)) {
      throw new Error("Cannot reuse previous passwords");
    }
  }
};

UserSchema.methods.incLoginAttempts = async function () {
  const MAX_ATTEMPTS = 5;
  const BASE_DELAY = 1 * 60 * 1000;
  if (this.lockUntil && this.lockUntil < Date.now()) {
    this.loginAttempts = 1;
    this.lockUntil = undefined;
  } else {
    this.loginAttempts += 1;
  }
  if (this.loginAttempts > MAX_ATTEMPTS) {
    const delay = Math.pow(2, this.loginAttempts - MAX_ATTEMPTS) * BASE_DELAY;
    this.lockUntil = new Date(Date.now() + delay);
  }
  await this.save({ validateBeforeSave: false });
};

UserSchema.methods.resetLoginState = function (ip, device) {
  this.loginAttempts = 0;
  this.lockUntil = undefined;
  this.lastLogin = {
    ip,
    device,
    timestamp: new Date(),
  };
};

UserSchema.methods.generateBackupCodes = async function () {
  const codes = Array(5)
    .fill()
    .map(async () => ({
      code: await bcrypt.hash(crypto.randomBytes(8).toString("hex"), 10),
      used: false,
    }));
  this.backupCodes = codes;
};

UserSchema.methods.changedPasswordAfter = function (JWTTimestamp) {
  if (this.passwordChangedAt) {
    const changedTimestamp = parseInt(
      this.passwordChangedAt.getTime() / 1000,
      10
    );
    return JWTTimestamp < changedTimestamp;
  }
  return false;
};

UserSchema.methods.generatePasswordResetToken = function () {
  const resetToken = crypto.randomBytes(32).toString("hex");

  this.passwordResetToken = crypto
    .createHash("sha256")
    .update(resetToken)
    .digest("hex");
  this.passwordResetTokenExpiration = Date.now() + 15 * 60 * 1000;

  return resetToken;
};

// ==============================
// Static Fields
// ==============================
UserSchema.statics.authenticateToken = async function (token) {
  try {
    const decoded = jwt.verify(token, JWT_REFRESH_SECRET);

    const user = await this.findById(decoded._id);

    if (!user) {
      throw new ApiError(StatusCodes.NOT_FOUND, "User not found");
    }
    return user;
  } catch (error) {
    if (error instanceof jwt.TokenExpiredError) {
      throw new ApiError(StatusCodes.UNAUTHORIZED, "Refresh token expired");
    }
    if (error instanceof jwt.JsonWebTokenError) {
      throw new ApiError(StatusCodes.UNAUTHORIZED, "Invalid refresh token");
    }
    throw error;
  }
};

// ==============================
// Virtual Fields
// ==============================
UserSchema.virtual("postsList", {
  ref: "Post",
  localField: "_id",
  foreignField: "author",
  justOne: false,
});

UserSchema.virtual("commentsList", {
  ref: "Comment",
  localField: "_id",
  foreignField: "author",
  justOne: false,
});

UserSchema.virtual("isLocked").get(function () {
  return !!(this.lockUntil && this.lockUntil > Date.now());
});

// ==============================
// Virtual Fields in Json
// ==============================
UserSchema.set("toObject", { virtuals: true });
UserSchema.set("toJSON", { virtuals: true });

// ==============================
// Indexes
// ==============================
UserSchema.index({ "tokens.token": 1 });
UserSchema.index({ isEmailVerified: 1 });
UserSchema.index({ failedLoginAttempts: 1 });
UserSchema.index({ fullName: "text", userName: "text", bio: "text" });
UserSchema.index({ role: 1, isEmailVerified: 1 });
UserSchema.index({ isActive: 1, isSuspended: 1 });
UserSchema.index({ "refreshTokens.token": 1 });
UserSchema.index({ subscriptionTier: 1 });
UserSchema.index({ popularityScore: -1 });
UserSchema.index({
  isActive: 1,
  isSuspended: 1,
  role: 1,
  isEmailVerified: 1,
});
UserSchema.index({
  followersCount: -1,
  popularityScore: -1,
  lastTrendingUpdate: -1,
});
UserSchema.index(
  { isSuspended: 1 },
  {
    partialFilterExpression: { isSuspended: true },
  }
);

// ==============================
// Plugins
// ==============================
UserSchema.plugin(softDeletePlugin);
UserSchema.plugin(sanitize);
UserSchema.plugin(leanVirtuals);
UserSchema.plugin(leanGetters);

// ==============================
// Export Model
// ==============================
const User = mongoose.model("User", UserSchema);

export default User;
