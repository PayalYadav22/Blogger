import mongoose from "mongoose";
import asyncHandler from "../../middleware/asyncHandler.middleware.js";
import User from "../../models/user.model.js";
import ApiError from "../../utils/apiError.js";
import ApiResponse from "../../utils/apiResponse.js";
import { StatusCodes } from "http-status-codes";
import logger from "../../logger/winston.logger.js";
import sendEmail from "../../utils/email.js";
import {
  uploadFileToCloudinary,
  deleteFileFromCloudinary,
} from "../../config/cloudinary.config.js";

const UserController = {
  getLoggedInUser: asyncHandler(async (req, res) => {
    const userId = req.user._id;

    if (!userId || !mongoose.Types.ObjectId.isValid(userId)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid User Id.");
    }

    const user = await User.findById(userId)
      .select(
        "+fullName +userName +email +phone +gender +dateOfBirth +bio +role +socialLinks"
      )
      .lean({ getters: true });

    if (!user) {
      throw new ApiError(StatusCodes.NOT_FOUND, "User not found");
    }

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
      },
      "Logged-in user fetched successfully"
    ).send(res);
  }),

  updateUserProfile: asyncHandler(async (req, res) => {
    const userId = req.user._id;

    const {
      fullName,
      bio,
      gender,
      dateOfBirth,
      socialLinks,
      location,
      specialization,
      authorBio,
    } = req.body;

    // Start a session and transaction
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      // Retrieve the user to update, excluding sensitive fields
      const user = await User.findById(userId)
        .select("-password -tokens")
        .session(session);

      if (!user) {
        throw new ApiError(StatusCodes.NOT_FOUND, "User not found");
      }

      // Update only provided fields
      user.fullName = fullName || user.fullName;
      user.bio = bio || user.bio;
      user.gender = gender || user.gender;
      user.dateOfBirth = dateOfBirth ? new Date(dateOfBirth) : user.dateOfBirth;
      user.socialLinks = socialLinks
        ? { ...user.socialLinks, ...socialLinks }
        : user.socialLinks;
      user.location = location || user.location;
      user.specialization = specialization || user.specialization;
      user.authorBio = authorBio || user.authorBio;

      // Update lastUpdated field to current date
      user.lastUpdated = new Date();

      // Save the updated user profile with transaction support
      await user.save({ validateBeforeSave: false, session });

      // Commit the transaction and end the session
      await session.commitTransaction();
      session.endSession();

      // Return the updated user profile in the response
      return new ApiResponse(
        StatusCodes.OK,
        {
          fullName: user.fullName,
          userName: user.userName,
          email: user.email,
          phone: user.phone,
          bio: user.bio,
          gender: user.gender,
          dateOfBirth: user.dateOfBirth,
          avatar: user.avatar,
          socialLinks: user.socialLinks,
          location: user.location,
          specialization: user.specialization,
          authorBio: user.authorBio,
          lastUpdated: user.lastUpdated,
        },
        "Profile updated successfully"
      ).send(res);
    } catch (error) {
      // Rollback the transaction if an error occurs
      await session.abortTransaction();
      session.endSession();

      // Log the error for debugging purposes (in production, log appropriately)
      console.error(error);

      // Throw the error to be handled by the global error handler
      throw new ApiError(StatusCodes.INTERNAL_SERVER_ERROR, error.message);
    }
  }),

  changeUserPassword: asyncHandler(async (req, res) => {
    const { oldPassword, newPassword } = req.body;

    // Validate the new password to ensure it's different from the old password
    if (oldPassword === newPassword) {
      throw new ApiError(
        StatusCodes.CONFLICT,
        "New password must be different from the old one"
      );
    }

    // Start a session for transaction support
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      // Fetch the current user and include the password field (ensure proper security)
      const user = await User.findById(req.user._id)
        .select("+password")
        .session(session);

      if (!user) {
        throw new ApiError(StatusCodes.NOT_FOUND, "User not found");
      }

      // Compare the old password with the stored password
      const isValid = await user.comparePassword(oldPassword);

      if (!isValid) {
        throw new ApiError(
          StatusCodes.UNAUTHORIZED,
          "Invalid current password"
        );
      }

      // Hash and update the password (if hashing is not already handled in the schema)
      user.password = newPassword;

      // Save the updated user with the new password (ensure it's hashed before saving)
      await user.save({ validateBeforeSave: false }, { session });

      // Attempt to send an email notification about the password change
      try {
        await sendEmail({
          to: user.email,
          subject: "Security Alert: Password Changed",
          template: "passwordChanged",
          context: { name: user.fullName },
        });
      } catch (err) {
        // Log any failure in sending the email for further investigation
        logger.error(
          `Password change email failed for user ${user.email}: ${err.message}`
        );

        // If email sending fails, abort the transaction
        await session.abortTransaction();
        session.endSession();

        throw new ApiError(
          StatusCodes.INTERNAL_SERVER_ERROR,
          "Failed to send notification email"
        );
      }

      // Commit the transaction if everything succeeds
      await session.commitTransaction();
      session.endSession();

      // Respond with a success message once the password change is complete
      return new ApiResponse(
        StatusCodes.OK,
        "Password changed successfully"
      ).send(res);
    } catch (err) {
      // Abort the transaction if an error occurs
      await session.abortTransaction();
      session.endSession();
      logger.error(
        `Password change failed for user ${req.user._id}: ${err.message}`
      );

      // Re-throw the error to be caught by the global error handler
      throw new ApiError(StatusCodes.INTERNAL_SERVER_ERROR, err.message);
    }
  }),

  updateUserAvatar: asyncHandler(async (req, res) => {
    const userId = req.user._id;

    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      // Step 1: Fetch user inside session
      const user = await User.findById(userId).session(session);

      if (!user) {
        throw new ApiError(StatusCodes.NOT_FOUND, "User not found");
      }

      // Step 2: Validate uploaded file path
      const avatarPath = req.file?.path;

      if (!avatarPath) {
        throw new ApiError(StatusCodes.BAD_REQUEST, "Avatar image is required");
      }

      // Step 3: Upload new avatar to Cloudinary
      const newAvatar = await uploadFileToCloudinary(avatarPath);
      if (!newAvatar?.public_id || !newAvatar?.secure_url) {
        throw new ApiError(
          StatusCodes.BAD_REQUEST,
          "Failed to upload new avatar"
        );
      }

      const oldAvatarPublicId = user.avatar?.public_id;

      // Step 4: Update user's avatar fields
      user.avatar = {
        publicId: newAvatar.public_id,
        url: newAvatar.secure_url,
      };

      // Step 5: Save updated user with session
      await user.save({ validateBeforeSave: false, session });

      // Step 6: Delete old avatar from Cloudinary after successful DB update
      if (oldAvatarPublicId) {
        try {
          await deleteFileFromCloudinary(oldAvatarPublicId);
        } catch (err) {
          logger.error(
            `Failed to delete old avatar [${oldAvatarPublicId}]: ${err.message}`
          );
        }
      }

      // Step 7: Commit transaction and send success response
      await session.commitTransaction();
      return new ApiResponse(
        StatusCodes.OK,
        { avatar: user.avatar },
        "Avatar updated successfully"
      ).send(res);
    } catch (error) {
      // Rollback transaction on any error
      await session.abortTransaction();
      logger.error(
        `Avatar update failed for user [${userId}]: ${error.message}`
      );
      throw new ApiError(StatusCodes.INTERNAL_SERVER_ERROR, error.message);
    } finally {
      // Always end session
      session.endSession();
    }
  }),

  getUserProfile: asyncHandler(async (req, res) => {
    const { userId } = req.params;

    if (!mongoose.Types.ObjectId.isValid(userId)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid User Id.");
    }

    const user = await User.findById(userId)
      .select(
        "-password -passwordHistory -otp -otpExpiration -tokens -refreshTokens -sessions -securityLogs -lastSensitiveOperations -backupCodes"
      )
      .populate([
        { path: "posts", select: "title slug createdAt" },
        { path: "comments", select: "content createdAt" },
        { path: "likes", select: "title slug" },
        { path: "bookmarks", select: "title slug" },
      ])
      .lean();

    if (!user) {
      throw new ApiError(StatusCodes.NOT_FOUND, "User not found.");
    }

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
      },
      "User Profile get successfully."
    ).send(res);
  }),

  updateUserPreferences: asyncHandler(async (req, res) => {
    const userId = req.user?._id;

    if (!mongoose.Types.ObjectId.isValid(userId)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid user ID format.");
    }

    const { notificationSettings, profilePrivacy } = req.body;

    if (!notificationSettings && !profilePrivacy) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "No preferences provided to update."
      );
    }

    const updateData = {};

    if (notificationSettings) {
      updateData.notificationSettings = notificationSettings;
    }

    if (profilePrivacy) {
      updateData.profilePrivacy = profilePrivacy;
    }

    // Start a session for transaction
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      // Perform the update inside the session
      const updatedUser = await User.findByIdAndUpdate(
        userId,
        { $set: updateData },
        { new: true, runValidators: true, session }
      ).select("notificationSettings profilePrivacy");

      if (!updatedUser) {
        throw new ApiError(StatusCodes.NOT_FOUND, "User not found.");
      }

      // Commit the transaction
      await session.commitTransaction();
      session.endSession();

      // Respond with success
      return new ApiResponse(
        StatusCodes.OK,
        updatedUser,
        "User preferences updated successfully."
      ).send(res);
    } catch (error) {
      // Rollback the transaction in case of error
      await session.abortTransaction();
      session.endSession();
      throw error;
    }
  }),

  deactivateUserAccount: asyncHandler(async (req, res) => {
    const userId = req.user._id;

    if (!mongoose.Types.ObjectId.isValid(userId)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid user ID format.");
    }

    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      const updatedUser = await User.findByIdAndUpdate(
        userId,
        {
          $set: {
            isActive: false,
            isSuspended: true,
            deactivatedAt: new Date(),
            deactivatedBy: userId,
          },
        },
        { new: true, runValidators: true, session }
      );

      if (!updatedUser) {
        throw new ApiError(StatusCodes.NOT_FOUND, "User not found.");
      }

      // Commit the transaction
      await session.commitTransaction();
      session.endSession();

      return new ApiResponse(
        StatusCodes.OK,
        {
          userId: updatedUser.id,
          fullName: updatedUser.fullName,
          userName: updatedUser.userName,
          email: updatedUser.email,
          phone: updatedUser.phone,
          bio: updatedUser.bio,
          gender: updatedUser.gender,
          dateOfBirth: updatedUser.dateOfBirth,
          avatar: updatedUser.avatar,
          socialLinks: updatedUser.socialLinks,
          location: updatedUser.location,
          specialization: updatedUser.specialization,
          authorBio: updatedUser.authorBio,
          deactivatedBy: updatedUser.deactivatedBy,
        },
        "User account deactivated successfully."
      ).send(res);
    } catch (error) {
      await session.abortTransaction();
      session.endSession();
      throw error;
    }
  }),

  getMyPosts: asyncHandler(async (req, res) => {
    const userId = req.user._id;

    if (!mongoose.Types.ObjectId.isValid(userId)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid Id.");
    }

    const user = await User.findById(userId).populate("posts").exec();

    if (!user) {
      return new ApiError(StatusCodes.NOT_FOUND, "User not found");
    }

    return new ApiResponse(
      StatusCodes.OK,
      { posts: user.posts },
      "User Post get Succesfully "
    ).send(res);
  }),

  getMyComments: asyncHandler(async (req, res) => {
    const userId = req.user._id;

    if (!mongoose.Types.ObjectId.isValid(userId)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid Id.");
    }

    const user = await User.findById(userId).populate("comments").exec();

    if (!user) {
      return new ApiError(StatusCodes.NOT_FOUND, "User not found");
    }

    return new ApiResponse(
      StatusCodes.OK,
      { Comment: user.comments },
      "User comments retrieved successfully"
    ).send(res);
  }),

  getMyBookmarks: asyncHandler(async (req, res) => {
    const userId = req.user._id;

    if (!mongoose.Types.ObjectId.isValid(userId)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid Id.");
    }

    const user = await User.findById(userId).populate("bookmarks").exec();

    if (!user) {
      return new ApiError(StatusCodes.NOT_FOUND, "User not found");
    }

    return new ApiResponse(
      StatusCodes.OK,
      { bookmarks: user.bookmarks },
      "User Bookmarks retrieved successfully"
    ).send(res);
  }),

  getMyLikes: asyncHandler(async (req, res) => {
    const userId = req.user._id;

    if (!mongoose.Types.ObjectId.isValid(userId)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid Id.");
    }

    const user = await User.findById(userId).populate("likes").exec();

    if (!user) {
      return new ApiError(StatusCodes.NOT_FOUND, "User not found");
    }

    return new ApiResponse(
      StatusCodes.OK,
      { likes: user.likes },
      "User Likes retrieved successfully"
    ).send(res);
  }),

  getMySubscription: asyncHandler(async (req, res) => {
    const userId = req.user._id;

    if (!mongoose.Types.ObjectId.isValid(userId)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid Id.");
    }

    const user = await User.findById(userId).select(
      "subscriptionTier isPremium"
    );

    if (!user) {
      return new ApiError(StatusCodes.NOT_FOUND, "User not found");
    }

    return new ApiResponse(
      StatusCodes.OK,
      {
        subscriptionTier: user.subscriptionTier,
        isPremium: user.isPremium,
      },
      "Subscription details fetched successfully"
    ).send(res);
  }),

  updateMySubscription: asyncHandler(async (req, res) => {
    const userId = req.user._id;

    const { subscriptionTier } = req.body;

    const validTiers = ["free", "basic", "premium"];

    if (!validTiers.includes(subscriptionTier)) {
      return new ApiError(
        StatusCodes.BAD_REQUEST,
        `Invalid subscription tier. Must be one of: ${validTiers.join(", ")}.`
      );
    }

    const user = await User.findById(userId);

    if (!user) {
      return new ApiError(StatusCodes.NOT_FOUND, "User not found.");
    }

    user.subscriptionTier = subscriptionTier;
    user.isPremium = subscriptionTier === "premium";

    await user.save({ validateBeforeSave: false });

    return new ApiResponse(
      StatusCodes.OK,
      {
        subscriptionTier: user.subscriptionTier,
        isPremium: user.isPremium,
      },
      "Subscription updated successfully."
    ).send(res);
  }),

  searchUsers: asyncHandler(async (req, res) => {
    const {
      query,
      limit = 10,
      page = 1,
      isVerified,
      createdBefore,
      createdAfter,
    } = req.query;

    if (!query) {
      return new ApiError(StatusCodes.BAD_REQUEST, "Search query is required");
    }

    const searchRegex = new RegExp(query, "i");
    const skip = (page - 1) * limit;

    const filter = {
      $and: [
        {
          $or: [
            { fullName: searchRegex },
            { userName: searchRegex },
            { email: searchRegex },
            { phone: searchRegex },
            { role: searchRegex },
            { gender: searchRegex },
            { location: searchRegex },
          ],
        },
        { isActive: true },
        { isSuspended: false },
      ],
    };

    if (isVerified !== undefined) {
      filter.$and.push({ isVerified: isVerified === "true" });
    }

    if (createdBefore) {
      filter.$and.push({ createdAt: { $lte: new Date(createdBefore) } });
    }

    if (createdAfter) {
      filter.$and.push({ createdAt: { $gte: new Date(createdAfter) } });
    }

    const users = await User.find(filter)
      .select("fullName userName email phone avatar location role createdAt")
      .limit(Number(limit))
      .skip(Number(skip))
      .sort({ createdAt: -1 })
      .lean();

    const totalResults = await User.countDocuments(filter);

    return new ApiResponse(
      StatusCodes.OK,
      {
        users,
        count: users.length,
        totalResults,
        currentPage: Number(page),
        totalPages: Math.ceil(totalResults / limit),
      },
      "Users fetched successfully"
    ).send(res);
  }),

  getPopularUsers: asyncHandler(async (req, res) => {
    const users = await User.find({ isActive: true })
      .sort({ popularityScore: -1 })
      .limit(10)
      .select(
        "fullName userName avatar.url followersCount followingCount popularityScore"
      );

    if (!users || users.length === 0) {
      throw new ApiError(StatusCodes.NOT_FOUND, "No popular users found.");
    }

    return new ApiResponse(
      StatusCodes.OK,
      users,
      "Popular users fetched successfully"
    ).send(res);
  }),

  getMyActivity: asyncHandler(async (req, res) => {
    const userId = req.user?._id;

    if (!userId) {
      throw new ApiError(StatusCodes.UNAUTHORIZED, "Unauthorized access.");
    }

    const user = await User.findById(userId)
      .select(
        "fullName userName avatar.url postCount views totalViews popularityScore lastActivityAt posts comments likes bookmarks"
      )
      .populate([
        { path: "posts", select: "title slug createdAt" },
        { path: "comments", select: "content post createdAt" },
        { path: "likes", select: "title slug createdAt" },
        { path: "bookmarks", select: "title slug createdAt" },
      ]);

    if (!user) {
      throw new ApiError(StatusCodes.NOT_FOUND, "User not found.");
    }

    return new ApiResponse(
      StatusCodes.OK,
      user,
      "User activity fetched successfully."
    ).send(res);
  }),
};

export default UserController;
