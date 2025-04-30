import { StatusCodes } from "http-status-codes";
import Like from "../../models/like.model.js";
import asyncHandler from "../../middleware/asyncHandler.middleware.js";
import ApiError from "../../utils/apiError.js";
import ApiResponse from "../../utils/apiResponse.js";
import mongoose from "mongoose";

const LikeController = {
  toggleLike: asyncHandler(async (req, res) => {
    const userId = req.user._id;
    const { postId } = req.params;

    if (!mongoose.Types.ObjectId.isValid(postId)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid Id.");
    }

    if (!postId) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Post ID is required.");
    }

    let like = await Like.findOne({ post: postId, user: userId });

    if (like) {
      if (like.isDeleted) {
        like.isDeleted = false;
        await like.save({ validateBeforeSave: false });
        return new ApiResponse(
          StatusCodes.OK,
          { liked: true },
          "Post liked again"
        ).send(res);
      } else {
        like.isDeleted = true;
        await like.save({ validateBeforeSave: false });
        return new ApiResponse(
          StatusCodes.OK,
          { liked: false },
          "Post unliked"
        ).send(res);
      }
    }

    await Like.create({ post: postId, user: userId });

    return new ApiResponse(
      StatusCodes.CREATED,
      { liked: true },
      "Post liked"
    ).send(res);
  }),

  getPostLikes: asyncHandler(async (req, res) => {
    const { postId } = req.params;

    if (!mongoose.Types.ObjectId.isValid(postId)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid Id.");
    }

    if (!postId) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Post ID is required.");
    }

    const likes = await Like.find({ post: postId, isDeleted: false }).populate(
      "user",
      "fullName email"
    );

    return new ApiResponse(
      StatusCodes.OK,
      { likes },
      `${likes.length} users liked this post`
    ).send(res);
  }),

  getUserLikedPosts: asyncHandler(async (req, res) => {
    const { userId } = req.params;

    if (!mongoose.Types.ObjectId.isValid(userId)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid Id.");
    }

    if (!userId) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "User ID is required.");
    }

    const likes = await Like.find({ user: userId, isDeleted: false })
      .populate("post")
      .populate("user", "fullName email");

    if (likes.length === 0) {
      throw new ApiError(StatusCodes.NOT_FOUND, "No liked posts found.");
    }

    const likedPosts = likes.map((like) => like.post);

    return new ApiResponse(
      StatusCodes.OK,
      { likedPosts },
      `${likedPosts.length} posts liked by this user`
    ).send(res);
  }),

  isPostLikedByUser: asyncHandler(async (req, res) => {
    const { userId, postId } = req.params;

    [userId, postId].map((i) => {
      if (!mongoose.Types.ObjectId.isValid(i)) {
        throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid Id.");
      }
    });

    if (!userId || !postId) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "User ID and Post ID are required."
      );
    }

    const isLiked = await Like.exists({
      user: userId,
      post: postId,
      isDeleted: false,
    });

    return new ApiResponse(
      StatusCodes.OK,
      { isLiked },
      isLiked ? "User has liked this post" : "User has not liked this post"
    ).send(res);
  }),

  countPostLikes: asyncHandler(async (req, res) => {
    const { postId } = req.params;

    if (!mongoose.Types.ObjectId.isValid(postId)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid Id.");
    }

    if (!postId) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Post ID is required.");
    }

    const likeCount = await Like.countDocuments({
      post: postId,
      isDeleted: false,
    });

    return new ApiResponse(
      StatusCodes.OK,
      { likeCount },
      `Post has been liked ${likeCount} times.`
    ).send(res);
  }),
};

export default LikeController;
