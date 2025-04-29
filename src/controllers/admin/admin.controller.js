import mongoose from "mongoose";
import asyncHandler from "../../middleware/asyncHandler.middleware.js";
import User from "../../models/user.model.js";
import ApiError from "../../utils/apiError.js";
import ApiResponse from "../../utils/apiResponse.js";
import { StatusCodes } from "http-status-codes";
import SecurityLog from "../../models/SecurityLog.js";
import sendEmail from "../../utils/email.js";

const AdminController = {
  getAllUsers: asyncHandler(async (req, res) => {
    const {
      query,
      limit = 10,
      page = 1,
      isVerified,
      createdBefore,
      createdAfter,
    } = req.query;

    const skip = (page - 1) * limit;

    const filter = {
      $and: [{ isActive: true }, { isSuspended: false }],
    };

    // If query is provided, add regex search to filter
    if (query) {
      const searchRegex = new RegExp(query, "i");
      filter.$and.push({
        $or: [
          { fullName: searchRegex },
          { userName: searchRegex },
          { email: searchRegex },
          { phone: searchRegex },
          { role: searchRegex },
          { gender: searchRegex },
          { location: searchRegex },
        ],
      });
    }

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
      .select(
        "fullName userName email phone avatar location role gender dateOfBirth createdAt"
      )
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

  getReportedUsers: asyncHandler(async (req, res) => {
    const users = await User.find({
      reportedBy: { $exists: true, $not: { $size: 0 } },
    })
      .select("fullName userName email reportedBy")
      .populate({
        path: "reportedBy",
        select: "fullName userName email",
      });

    return new ApiResponse(
      StatusCodes.OK,
      { count: users.length, data: users },
      "Reported users fetched successfully"
    ).send(res);
  }),

  getUser: asyncHandler(async (req, res) => {
    const { id } = req.params;

    // Validate MongoDB ObjectId
    if (!mongoose.Types.ObjectId.isValid(id)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid Id.");
    }

    const user = await User.findById(id).select(
      "fullName userName phone email gender role dateOfBirth socialLinks"
    );

    if (!user) {
      throw new ApiError(StatusCodes.NOT_FOUND, "User not found");
    }

    const responseData = {
      userId: user._id,
      fullName: user.fullName,
      userName: user.userName,
      phone: user.phone,
      email: user.email,
      gender: user.gender,
      role: user.role,
      dateOfBirth: user.dateOfBirth,
      socialLinks: user.socialLinks,
    };

    new ApiResponse(
      StatusCodes.OK,
      responseData,
      "User fetched successfully."
    ).send(res);
  }),

  updateUser: asyncHandler(async (req, res) => {
    const { id: userId } = req.params;
    const updates = req.body;

    // Whitelisted fields for update
    const allowedFields = new Set([
      "fullName",
      "userName",
      "bio",
      "gender",
      "location",
      "socialLinks",
      "backupEmail",
      "specialization",
      "authorBio",
      "role",
      "isSuspended",
      "isActive",
      "postLimit",
      "profilePrivacy",
      "subscriptionTier",
      "notificationSettings",
      "languagePreference",
      "timezone",
    ]);

    // Filter updates to include only allowed fields
    const filtered = {};
    for (const key in updates) {
      if (allowedFields.has(key)) filtered[key] = updates[key];
    }

    // Validate email if present
    if (filtered.backupEmail && !validator.isEmail(filtered.backupEmail)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid backup email.");
    }

    const updatedUser = await User.findByIdAndUpdate(
      userId,
      { $set: filtered },
      { new: true, runValidators: true }
    ).select("-password -tokens -refreshTokens");

    if (!updatedUser) {
      throw new ApiError(StatusCodes.NOT_FOUND, "User not found.");
    }

    // Log the update
    await SecurityLog.create({
      action: "ADMIN_UPDATE_USER_PROFILE",
      performedBy: req.user._id,
      targetUser: userId,
      timestamp: new Date(),
    });

    const responseData = {
      userId: updatedUser._id,
      fullName: updatedUser.fullName,
      userName: updatedUser.userName,
      phone: updatedUser.phone,
      email: updatedUser.email,
      gender: updatedUser.gender,
      role: updatedUser.role,
      dateOfBirth: updatedUser.dateOfBirth,
      socialLinks: updatedUser.socialLinks,
    };

    new ApiResponse(
      StatusCodes.OK,
      responseData,
      "User updated successfully."
    ).send(res);
  }),

  suspendUser: asyncHandler(async (req, res) => {
    const { id } = req.params;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid id.");
    }

    // Update the user's suspension status
    const updatedUser = await User.findByIdAndUpdate(
      id,
      { isSuspended: true },
      { new: true, runValidators: true }
    ).select("-password -tokens -refreshTokens");

    if (!updatedUser) {
      throw new ApiError(StatusCodes.NOT_FOUND, "User not found.");
    }

    // Log the suspension action
    await SecurityLog.create({
      action: "ADMIN_SUSPEND_USER",
      performedBy: req.user._id,
      targetUser: id,
      timestamp: new Date(),
    });

    await sendEmail({
      to: updatedUser.email,
      subject: "Account Suspended",
      template: "suspendUser",
      context: { name: updatedUser.fullName, email: updatedUser.email },
    });

    const responseData = {
      userId: updatedUser._id,
      fullName: updatedUser.fullName,
      userName: updatedUser.userName,
      phone: updatedUser.phone,
      email: updatedUser.email,
      gender: updatedUser.gender,
      role: updatedUser.role,
      dateOfBirth: updatedUser.dateOfBirth,
      socialLinks: updatedUser.socialLinks,
    };

    return new ApiResponse(
      StatusCodes.OK,
      responseData,
      `User suspended successfully.`
    ).send(res);
  }),

  unsuspendUser: asyncHandler(async (req, res) => {
    const { id } = req.params;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid id.");
    }

    // Update the user's suspension status
    const updatedUser = await User.findByIdAndUpdate(
      id,
      { isSuspended: false },
      { new: true, runValidators: true }
    ).select("-password -tokens -refreshTokens");

    if (!updatedUser) {
      throw new ApiError(StatusCodes.NOT_FOUND, "User not found.");
    }

    // Log the suspension action
    await SecurityLog.create({
      action: "ADMIN_ACTIVATE_USER",
      performedBy: req.user._id,
      targetUser: id,
      timestamp: new Date(),
    });

    await sendEmail({
      to: updatedUser.email,
      subject: "Account Active",
      template: "activeUser",
      context: { name: updatedUser.fullName, email: updatedUser.email },
    });

    const responseData = {
      userId: updatedUser._id,
      fullName: updatedUser.fullName,
      userName: updatedUser.userName,
      phone: updatedUser.phone,
      email: updatedUser.email,
      gender: updatedUser.gender,
      role: updatedUser.role,
      dateOfBirth: updatedUser.dateOfBirth,
      socialLinks: updatedUser.socialLinks,
    };

    return new ApiResponse(
      StatusCodes.OK,
      responseData,
      `User activated successfully.`
    ).send(res);
  }),

  promoteUser: asyncHandler(async (req, res) => {
    const { id } = req.params;
    const { newRole } = req.body;

    const validRoles = [
      "admin",
      "editor",
      "writer",
      "viewer",
      "moderator",
      "contributor",
      "subscriber",
    ];

    if (!validRoles.includes(newRole)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid role .");
    }

    const user = await User.findById(id);

    if (!user) {
      throw new ApiError(StatusCodes.NOT_FOUND, "Invalid role .");
    }

    if (user.role === newRole) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "User is already in the specified role"
      );
    }

    user.role = newRole;
    await user.save({ validateBeforeSave: false });

    return new ApiResponse(
      StatusCodes.OK,
      `User has been promoted to ${newRole}`
    ).send(res);
  }),

  deleteUser: asyncHandler(async (req, res) => {
    const { id } = req.params;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid Id.");
    }

    const user = await User.findById(id);

    if (!user) {
      throw new ApiError(StatusCodes.NOT_FOUND, "User not found .");
    }

    user.isActive = false;
    user.deactivatedAt = new Date();
    user.deactivatedBy = req.user?._id || null;

    await user.save({ validateBeforeSave: false });

    return new ApiResponse(
      StatusCodes.OK,
      "User account deactivated successfully."
    ).send(res);
  }),

  warnUser: asyncHandler(async (req, res) => {
    const { id } = req.params;

    const { reason } = req.body;

    if (!reason) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Warning reason is required");
    }

    const user = await User.findById(id);

    if (!user) {
      throw new ApiError(StatusCodes.NOT_FOUND, "User not found");
    }

    user.warnings.push({
      reason,
      issuedBy: req.user._id,
    });

    await user.save({ validateBeforeSave: false });

    return new ApiResponse(
      StatusCodes.OK,
      `User ${user.fullName} has been warned successfully`
    ).send(res);
  }),
};

export default AdminController;
