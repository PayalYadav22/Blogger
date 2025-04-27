// Import necessary libraries and plugins
import mongoose from "mongoose";
import bcrypt from "bcrypt";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import validator from "validator";
import {
  softDeletePlugin,
  sanitize,
  leanVirtuals,
  leanGetters,
} from "../plugins/index.js";

// Constants
const OTP_EXPIRATION_TIME = 5 * 60 * 1000; // 5 minutes
const SOLTROUND = 15;

// Utility function for array length validation
function arrayLimit(val) {
  return val.length <= 5000;
}

// Security configuration constants
const SECURITY_CONFIG = {
  MAX_OTP_ATTEMPTS: 5,
  OTP_BLOCK_DURATION: 15 * 60 * 1000, // 15 minutes
  MAX_FAILED_LOGINS: 5,
  LOGIN_BLOCK_DURATION: 15 * 60 * 1000,
  PASSWORD_HISTORY_LIMIT: 5,
  PASSWORD_REUSE_COOLDOWN: 365 * 24 * 60 * 60 * 1000, // 1 year
};

// User Schema definition
const UserSchema = new mongoose.Schema(
  {
    // Basic account info
    email: {
      type: String,
      required: true,
      unique: true,
      trim: true,
      lowercase: true,
      validate: [validator.isEmail, "Invalid email address"],
    },
    password: {
      type: String,
      required: true,
      select: false,
      validate: {
        validator: (pass) =>
          validator.isStrongPassword(pass, {
            minLength: 8,
            minLowercase: 1,
            minUppercase: 1,
            minNumbers: 1,
            minSymbols: 1,
          }),
        message:
          "Password must be at least 8 chars with 1 lowercase, 1 uppercase, 1 number, and 1 symbol",
      },
    },

    // Security fields
    passwordHistory: {
      type: [String],
      select: false,
      default: [],
      validate: {
        validator: function (v) {
          return v.length <= 5;
        },
        message: "Password history cannot exceed 5 entries.",
      },
    },
    otp: { type: String, select: false },
    otpExpiration: { type: Date, select: false },
    scannerSecret: { type: String, default: null, select: false },
    twoFactorEnabled: { type: Boolean, default: false },

    // Session/token handling
    tokens: [
      {
        token: { type: String, required: true },
        createdAt: { type: Date, default: Date.now },
      },
    ],
    refreshTokens: [
      {
        token: { type: String, required: true },
        createdAt: { type: Date, default: Date.now },
        expiresAt: { type: Date, required: true },
      },
    ],

    // Profile fields
    displayName: { type: String, required: true },
    bio: { type: String, default: "" },
    avatar: {
      url: String,
      publicId: String,
    },
    socialLinks: {
      website: String,
      twitter: String,
      github: String,
    },
    location: String,

    // Role and permissions
    role: {
      type: String,
      enum: ["admin", "writer", "editor", "viewer"],
      default: "writer",
    },
    postLimit: { type: Number, default: 10 },

    // Account status flags
    isActive: { type: Boolean, default: true },
    isSuspended: { type: Boolean, default: false },
    deactivatedAt: { type: Date, select: false },
    deactivatedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" },

    // Content activity tracking
    postCount: { type: Number, default: 0 },
    views: { type: Number, default: 0 },
    totalViews: { type: Number, default: 0 },
    popularityScore: { type: Number, default: 0 },
    lastTrendingUpdate: Date,

    // Subscription fields
    isPremium: { type: Boolean, default: false, select: false },
    subscriptionTier: {
      type: String,
      enum: ["free", "basic", "premium"],
      default: "free",
    },

    // Notification preferences
    notificationSettings: {
      emailOnMention: { type: Boolean, default: true },
      emailOnFollow: { type: Boolean, default: true },
    },

    // Optional user details
    backupEmail: {
      type: String,
      validate: [validator.isEmail, "Invalid backup email"],
    },
    authorBio: {
      type: String,
      default: "",
      maxLength: 500,
    },
    specialization: { type: String, default: "" },

    // Social media links
    socialMediaLinks: {
      twitter: { type: String, default: "" },
      linkedin: { type: String, default: "" },
      github: { type: String, default: "" },
      instagram: { type: String, default: "" },
      website: { type: String, default: "" },
    },

    // Account verification
    isEmailVerified: { type: Boolean, default: false },
    emailVerificationToken: { type: String, select: false },
    emailVerificationTokenExpiration: { type: Date, select: false },
    emailVerifiedAt: { type: Date, select: false },

    // Login and reset tracking
    failedLoginAttempts: { type: Number, default: 0 },
    lastLoginAttempt: { type: Date, select: false },
    accountLockTime: { type: Date, select: false },
    passwordResetToken: { type: String, select: false },
    passwordResetTokenExpiration: { type: Date, select: false },
    failedResetAttempts: { type: Number, default: 0 },
    lastPasswordResetRequest: { type: Date },
    passwordResetCooldown: { type: Number, default: 10 * 60 * 1000 },
    lastPasswordChange: { type: Date, default: Date.now },

    // User privacy settings
    profilePrivacy: {
      type: String,
      enum: ["public", "private", "friends"],
      default: "public",
    },

    // Miscellaneous tracking
    lastLogin: {
      ip: String,
      device: String,
      timestamp: Date,
    },
    passwordResetHistory: [
      {
        ip: String,
        timestamp: Date,
      },
    ],
    otpAttempts: { type: Number, default: 0 },
    otpBlockedUntil: Date,
    blockedUsers: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
    lastSensitiveOperations: {
      type: Map,
      of: Date,
      default: {},
      select: false,
    },

    // Social/follow data
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

    // Legacy account migration
    isLegacyAccount: { type: Boolean, default: false },
    migrationStatus: String,

    // Localization
    languagePreference: { type: String, default: "en" },
    timezone: { type: String, default: "UTC" },
  },
  { timestamps: true }
);

// Hash password before saving
UserSchema.pre("save", async function (next) {
  if (this.isModified("password")) {
    if (this.password) {
      this.passwordHistory = [
        this.password,
        ...this.passwordHistory.slice(0, 4),
      ];
    }
    const salt = await bcrypt.genSalt(SOLTROUND);
    this.password = await bcrypt.hash(this.password, salt);
    this.lastPasswordChange = new Date();
  }
  next();
});

// Instance methods for user operations (auth, OTP, reset, social, etc.)
UserSchema.methods = {
  // Mark email as verified
  async verifyEmail() {
    this.isEmailVerified = true; // Set verification flag
    this.emailVerifiedAt = new Date(); // Record the verification timestamp
    await this.save(); // Persist changes to the DB
  },

  // Compare a plaintext password with the hashed one in DB
  async comparePassword(password) {
    return bcrypt.compare(password, this.password); // Returns true if match
  },

  // Generate JWT access and refresh tokens
  async generateTokens() {
    const accessToken = jwt.sign(
      { _id: this._id, email: this.email }, // Payload for the token
      process.env.JWT_SECRET, // Secret key for signing
      { expiresIn: "15m" } // Access token lifespan
    );

    const refreshToken = jwt.sign(
      { _id: this._id, email: this.email },
      process.env.JWT_SECRET,
      { expiresIn: "7d" } // Longer lifespan for refresh token
    );

    const expiresAt = Date.now() + 7 * 24 * 60 * 60 * 1000; // 7 days from now
    this.refreshTokens.push({ token: refreshToken, expiresAt }); // Store refresh token in DB

    await this.save(); // Persist to DB

    return { accessToken, refreshToken }; // Return tokens to client
  },

  // Validate a given refresh token
  async verifyRefreshToken(refreshToken) {
    try {
      const decoded = jwt.verify(refreshToken, process.env.JWT_SECRET); // Verify signature
      const user = await this.findOne({
        _id: decoded._id,
        "refreshTokens.token": refreshToken, // Ensure token exists in DB
      }).select("+refreshTokens.token"); // Explicitly include the refreshTokens field

      if (!user) throw new Error("Invalid refresh token"); // Token not valid

      // Keep only non-expired refresh tokens
      user.refreshTokens = user.refreshTokens.filter(
        (rt) => rt.expiresAt > Date.now()
      );
      await user.save();

      // Create new access token
      const accessToken = jwt.sign(
        { _id: user._id, email: user.email },
        process.env.JWT_SECRET,
        { expiresIn: "15m" }
      );

      return accessToken;
    } catch (error) {
      throw new Error("Invalid or expired refresh token");
    }
  },

  // Remove a specific device's token
  async revokeDeviceToken(deviceId) {
    this.devices = this.devices.filter(
      (device) => device.deviceId !== deviceId
    );
    await this.save();
  },

  // Remove all device tokens (logout from all devices)
  async revokeAllDeviceTokens() {
    this.devices = []; // Clear device list
    await this.save();
  },

  // Remove all refresh tokens
  async invalidateRefreshTokens() {
    this.refreshTokens = [];
    await this.save();
  },

  // Generate a one-time password (OTP)
  async generateOTP() {
    const otp = crypto.randomBytes(3).toString("hex").toUpperCase(); // 6-char hex OTP
    this.otp = otp;
    this.otpExpiration = Date.now() + OTP_EXPIRATION_TIME; // Set expiry
    return otp;
  },

  // Regenerate scanner secret for 2FA setup
  async regenerateScannerSecret() {
    const newSecret = crypto.randomBytes(20).toString("hex"); // Secure 2FA secret
    this.scannerSecret = newSecret;
    await this.save();
    return newSecret;
  },

  // Check if the user can attempt login (not locked)
  async canAttemptLogin() {
    return !(this.accountLockTime && this.accountLockTime > Date.now());
  },

  // Register a failed login and possibly lock the account
  async registerFailedLogin() {
    this.failedLoginAttempts += 1;
    this.lastLoginAttempt = new Date();
    if (this.failedLoginAttempts >= 5) {
      this.accountLockTime = new Date(Date.now() + 15 * 60 * 1000); // Lock for 15 mins
    }
    await this.save();
  },

  // Follow another user
  async follow(followedUserId) {
    const existingFollow = await Follow.findOne({
      userId: this._id,
      followedId: followedUserId,
    });

    if (existingFollow) {
      throw new Error("You are already following this user.");
    }

    const follow = new Follow({
      userId: this._id,
      followedId: followedUserId,
    });

    await follow.save();

    this.followingCount += 1;
    await this.save();

    await User.findByIdAndUpdate(followedUserId, {
      $inc: { followersCount: 1 },
    });

    return follow;
  },

  // Unfollow a user
  async unfollow(followedUserId) {
    const follow = await Follow.findOneAndDelete({
      userId: this._id,
      followedId: followedUserId,
    });

    if (!follow) {
      throw new Error("You are not following this user.");
    }

    this.followingCount -= 1;
    await this.save();

    await User.findByIdAndUpdate(followedUserId, {
      $inc: { followersCount: -1 },
    });

    return follow;
  },

  // Get list of followers
  async getFollowers() {
    const followers = await Follow.find({ followedId: this._id })
      .populate("userId", "displayName email")
      .exec();
    return followers;
  },

  // Get list of users this user is following
  async getFollowing() {
    const following = await Follow.find({ userId: this._id })
      .populate("followedId", "displayName email")
      .exec();
    return following;
  },

  // Get follower count
  async getFollowersCount() {
    return Follow.countDocuments({ followedId: this._id });
  },

  // Get following count
  async getFollowingCount() {
    return Follow.countDocuments({ userId: this._id });
  },

  // Get paginated followers
  async getFollowers(page = 1, limit = 10) {
    const followers = await Follow.find({ followedId: this._id })
      .skip((page - 1) * limit)
      .limit(limit)
      .populate("userId", "displayName email")
      .exec();
    return followers;
  },

  // Handle password reset request with cooldown + security
  async requestPasswordReset() {
    const now = Date.now();
    const cooldownTime = this.passwordResetCooldown;
    const lastRequestTime = this.lastPasswordResetRequest;

    if (lastRequestTime && now - lastRequestTime < cooldownTime) {
      const remainingTime = Math.round(
        (cooldownTime - (now - lastRequestTime)) / 1000
      );
      throw new Error(
        `Please wait ${remainingTime} seconds before requesting a reset again.`
      );
    }

    if (this.failedResetAttempts >= 5) {
      throw new Error(
        "Too many failed reset attempts. Please try again later."
      );
    }

    const resetToken = crypto.randomBytes(20).toString("hex"); // Secure reset token
    this.passwordResetToken = resetToken;
    this.passwordResetTokenExpiration = Date.now() + 60 * 60 * 1000; // 1 hour
    this.failedResetAttempts = 0;
    this.lastPasswordResetRequest = now;

    await this.save();
    return resetToken;
  },

  // Increment counter for failed password reset attempts
  async incrementFailedResetAttempts() {
    this.failedResetAttempts += 1;
    if (this.failedResetAttempts >= 5) {
      this.passwordResetTokenExpiration = Date.now() + 15 * 60 * 1000; // Lockout
    }
    await this.save();
  },

  // Block another user
  async blockUser(userIdToBlock) {
    if (this.blockedUsers.includes(userIdToBlock)) {
      throw new Error("User already blocked");
    }
    this.blockedUsers.push(userIdToBlock);
    await this.save();
  },

  // Rate limit sensitive actions (like email/password changes)
  async canPerformSensitiveOperation(operationType) {
    const now = Date.now();
    const lastOperation = this.lastSensitiveOperations.get(operationType);
    const cooldown = 5 * 60 * 1000; // 5 minutes

    if (lastOperation && now - lastOperation < cooldown) {
      const remaining = Math.ceil((cooldown - (now - lastOperation)) / 1000);
      throw new Error(
        `Please wait ${remaining} seconds before performing this operation again`
      );
    }

    this.lastSensitiveOperations.set(operationType, now);
    await this.save();
    return true;
  },

  // Prevent user from reusing a recent password
  async checkPasswordReuse(newPassword) {
    for (const oldHash of this.passwordHistory) {
      if (await bcrypt.compare(newPassword, oldHash)) {
        throw new Error("Cannot reuse recent passwords");
      }
    }
    return true;
  },
};

// Static methods on the model (for auth with tokens/OTP/scanner)
UserSchema.statics = {
  /**
   * Authenticates a user using a JWT token stored in the user's tokens array
   */
  async authenticateToken(token) {
    try {
      // Decode and verify the JWT token
      const decoded = jwt.verify(token, process.env.JWT_SECRET);

      // Look for the user with the matching token
      const user = await this.findOne({
        _id: decoded._id,
        "tokens.token": token,
      }).select("+tokens.token"); // Explicitly include tokens

      if (!user) throw new Error("Authentication failed");

      return user; // Return authenticated user
    } catch (error) {
      throw new Error("Authentication failed: " + error.message);
    }
  },

  /**
   * Authenticates a user by verifying a one-time password (OTP)
   */
  async authenticateOTP(email, otp) {
    // Find the user and include OTP fields
    const user = await this.findOne({ email }).select("+otp +otpExpiration");

    // Check OTP match and expiration
    if (user && user.otp === otp && user.otpExpiration > Date.now()) {
      user.otp = undefined; // Clear OTP once used
      user.otpExpiration = undefined;
      await user.save(); // Persist changes

      return user; // OTP is valid, return user
    }

    throw new Error("OTP authentication failed");
  },

  /**
   * Authenticates a user using a 2FA scanner secret (e.g., QR code-based auth)
   */
  async authenticateScanner(email, scannerSecret) {
    // Retrieve user with scanner secret
    const user = await this.findOne({ email }).select("+scannerSecret");

    // Validate 2FA is enabled and secrets match
    if (user && user.twoFactorEnabled && user.scannerSecret === scannerSecret) {
      return user; // Auth successful
    }

    throw new Error("Scanner authentication failed");
  },

  /**
   * Verifies a JWT token tied to a specific device
   */
  async verifyDeviceToken(deviceToken, deviceId) {
    try {
      // Decode and verify token
      const decoded = jwt.verify(deviceToken, process.env.JWT_SECRET);

      // Find user with matching device and token
      const user = await this.findOne({
        _id: decoded._id,
        "devices.deviceId": deviceId,
        "devices.token": deviceToken,
      }).select("+devices.token"); // Explicitly include tokens

      if (!user) throw new Error("Invalid device token");

      // Update last used timestamp for that device
      const device = user.devices.find((d) => d.deviceId === deviceId);
      device.lastUsed = Date.now();
      await user.save(); // Save updated timestamp

      return user; // Auth successful
    } catch (error) {
      throw new Error("Invalid or expired device token");
    }
  },
};

// Virtual fields
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

// Calculates how much of the user profile is complete
UserSchema.virtual("profileComplete").get(function () {
  const requiredFields = ["email", "displayName", "avatar.url"];
  const completedFields = requiredFields.filter((field) => {
    const parts = field.split(".");
    let value = this;
    for (const part of parts) {
      value = value[part];
      if (!value) return false;
    }
    return true;
  });
  return (completedFields.length / requiredFields.length) * 100;
});

// Virtuals in JSON output
UserSchema.set("toObject", { virtuals: true });
UserSchema.set("toJSON", { virtuals: true });

// Indexes for search and performance
UserSchema.index({ "tokens.token": 1 });
UserSchema.index({ isEmailVerified: 1 });
UserSchema.index({ failedLoginAttempts: 1 });
UserSchema.index({ displayName: "text", bio: "text" });
UserSchema.index({ role: 1, isEmailVerified: 1 });
UserSchema.index({ isActive: 1, isSuspended: 1 });
UserSchema.index({ email: 1 });
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

// Add custom plugins
UserSchema.plugin(softDeletePlugin);
UserSchema.plugin(sanitize);
UserSchema.plugin(leanVirtuals);
UserSchema.plugin(leanGetters);

// Create and export the model
const User = mongoose.model("User", UserSchema);
export default User;
