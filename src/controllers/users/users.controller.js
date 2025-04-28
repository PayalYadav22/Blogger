import mongoose from "mongoose";
import validator from "validator";
import asyncHandler from "../../middleware/asyncHandler.middleware.js";
import User from "../../models/user.model.js";
import ApiError from "../../utils/apiError.js";
import ApiResponse from "../../utils/apiResponse.js";
import { StatusCodes } from "http-status-codes";

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
      await user.save({ session });

      // Attempt to send an email notification about the password change
      try {
        await sendEmail({
          to: user.email,
          subject: "Security Alert: Password Changed",
          template: "passwordChanged",
          context: {
            name: user.fullName,
            timestamp: new Date().toLocaleString(),
            device: req.headers["user-agent"],
          },
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

  updateUserAvatar: asyncHandler(async (req, res) => {}),

  getUserProfile: asyncHandler(async (req, res) => {}),

  updateUserPreferences: asyncHandler(async (req, res) => {}),

  deactivateUserAccount: asyncHandler(async (req, res) => {}),

  getMyPosts: asyncHandler(async (req, res) => {}),

  getMyComments: asyncHandler(async (req, res) => {}),

  getMyBookmarks: asyncHandler(async (req, res) => {}),

  getMyLikes: asyncHandler(async (req, res) => {}),

  getMySubscription: asyncHandler(async (req, res) => {}),

  updateMySubscription: asyncHandler(async (req, res) => {}),

  searchUsers: asyncHandler(async (req, res) => {}),

  getPopularUsers: asyncHandler(async (req, res) => {}),

  getMyActivity: asyncHandler(async (req, res) => {}),
};

export default UserController;
