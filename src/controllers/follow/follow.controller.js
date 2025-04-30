import mongoose from "mongoose";
import Follow from "../../models/follow.model.js";
import asyncHandler from "../../middleware/asyncHandler.middleware.js";
import ApiError from "../../utils/apiError.js";
import { StatusCodes } from "http-status-codes";

const FollowController = {
  followUser: asyncHandler(async (req, res) => {
    const { userId, followedId } = req.body;

    [userId, followedId].map((i) => {
      if (!mongoose.Types.ObjectId.isValid(i)) {
        throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid Id.");
      }
    });

    if (userId.equals(followedId)) {
      return new ApiError(
        StatusCodes.BAD_REQUEST,
        "You cannot follow yourself."
      );
    }

    const existingFollow = await Follow.findOne({ userId, followedId });

    if (existingFollow) {
      await existingFollow.remove();
      return new ApiResponse(
        StatusCodes.OK,
        "Unfollowed the user successfully."
      ).send(res);
    } else {
      const follow = new Follow({
        userId,
        followedId,
      });

      await follow.save({ validateBeforeSave: false });
      return new ApiResponse(
        StatusCodes.OK,
        "Followed the user successfully."
      ).send(res);
    }
  }),

  unfollowUser: asyncHandler(async (req, res) => {
    const { userId, followedId } = req.body;

    [userId, followedId].map((i) => {
      if (!mongoose.Types.ObjectId.isValid(i)) {
        throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid Id.");
      }
    });

    if (!userId || !followedId) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "userId and followedId are required."
      );
    }

    const followRecord = await Follow.findOne({
      userId,
      followedId,
      isDeleted: false,
    });

    if (!followRecord) {
      throw new ApiError(
        StatusCodes.NOT_FOUND,
        "Follow relationship not found."
      );
    }

    followRecord.isDeleted = true;
    await followRecord.save({ validateBeforeSave: false });

    return new ApiResponse(StatusCodes.OK, "Unfollowed successfully.").send(
      res
    );
  }),

  checkIfFollowing: asyncHandler(async (req, res) => {
    const { userId, followedId } = req.query;

    if (!userId || !followedId) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "userId and followedId are required."
      );
    }

    const isFollowing = await Follow.exists({
      userId,
      followedId,
      isDeleted: false,
    });

    return new ApiResponse(
      StatusCodes.OK,
      { isFollowing: Boolean(isFollowing) },
      "Follow status retrieved"
    ).send(res);
  }),

  getFollowers: asyncHandler(async (req, res) => {
    const { userId } = req.params;

    if (!userId) {
      throw new ApiError(StatusCodes.BAD_REQUEST, null, "User ID is required");
    }

    const followers = await Follow.find({
      followedId: userId,
      isDeleted: false,
    })
      .populate("userId", "name username avatar")
      .lean();

    return new ApiResponse(
      StatusCodes.OK,
      { followers },
      "Followers fetched successfully"
    ).send(res);
  }),

  getFollowing: asyncHandler(async (req, res) => {
    const { userId } = req.params;

    if (!userId) {
      throw new ApiError(StatusCodes.BAD_REQUEST, null, "User ID is required");
    }

    const following = await Follow.find({ userId, isDeleted: false })
      .populate("followedId", "name username avatar")
      .lean();

    return new ApiResponse(
      StatusCodes.OK,
      { following },
      "Following list fetched successfully"
    ).send(res);
  }),
};

export default FollowController;
