import Comment from "../../models/comment.model.js";
import asyncHandler from "../../middleware/asyncHandler.middleware.js";
import { StatusCodes } from "http-status-codes";
import ApiError from "../../utils/apiError.js";
import ApiResponse from "../../utils/apiResponse.js";

const CommentController = {
  approveComment: asyncHandler(async (req, res) => {
    const { id } = req.params;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid Id.");
    }

    const comment = await Comment.findById(id);

    if (!comment) {
      throw new ApiError(StatusCodes.NOT_FOUND, "Comment not found");
    }

    if (comment.isApproved) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "This comment is already approved"
      );
    }

    comment.isApproved = true;
    await comment.save({ validateBeforeSave: false });

    return new ApiResponse(
      StatusCodes.OK,
      comment,
      "Comment approved successfully"
    ).send(res);
  }),

  createComment: asyncHandler(async (req, res) => {
    const { content, post, parent } = req.body;

    const author = req.user._id;

    if (!content || !post) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Content and Post ID are required."
      );
    }

    const comment = new Comment({
      content,
      author,
      post,
      parent: parent || null,
    });

    await comment.save({ validateBeforeSave: false });

    return new ApiResponse(
      StatusCodes.CREATED,
      comment,
      "Comment created successfully"
    ).send(res);
  }),

  deleteComment: asyncHandler(async (req, res) => {
    const { id } = req.params;
    const userId = req.user._id;
    const userRole = req.user.role;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid Id.");
    }

    const comment = await Comment.findById(id);

    if (!comment || comment.isDeleted) {
      throw new ApiError(
        StatusCodes.NOT_FOUND,
        "Comment not found or already deleted."
      );
    }

    if (!comment.author.equals(userId) && userRole !== "admin") {
      throw new ApiError(
        StatusCodes.CONFLICT,
        "You are not authorized to delete this comment."
      );
    }

    comment.contentHistory.push({
      content: comment.content,
      updatedAt: new Date(),
      updatedBy: userId,
    });

    comment.content = "[deleted]";
    comment.isDeleted = true;
    comment.deletedAt = new Date();

    await comment.save({ validateBeforeSave: false });

    return new ApiResponse(
      StatusCodes.OK,
      "Comment deleted successfully (soft delete)."
    ).send(res);
  }),

  dislikeComment: asyncHandler(async (req, res) => {
    const { id } = req.params;
    const userId = req.user._id;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid Id.");
    }

    const comment = await Comment.findById(id);

    if (!comment || comment.isDeleted) {
      throw new ApiError(404, "Comment not found or has been deleted.");
    }

    const hasDisliked = comment.dislikes.includes(userId);
    const hasLiked = comment.likes.includes(userId);

    if (hasDisliked) {
      comment.dislikes.pull(userId);
    } else {
      if (hasLiked) comment.likes.pull(userId);
      comment.dislikes.push(userId);
    }

    await comment.save({ validateBeforeSave: false });

    return new ApiResponse(
      StatusCodes.OK,
      {
        dislikesCount: comment.dislikes.length,
        likesCount: comment.likes.length,
      },
      hasDisliked ? "Dislike removed." : "Comment disliked."
    ).send(res);
  }),

  flagComment: asyncHandler(async (req, res) => {
    const { id } = req.params;
    const { reportReason } = req.body;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid Id.");
    }

    if (!reportReason || reportReason.trim().length === 0) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Report reason is required.");
    }

    const comment = await Comment.findById(id);

    if (!comment || comment.isDeleted) {
      throw new ApiError(StatusCodes.NOT_FOUND, "Comment not found.");
    }

    comment.isReported = true;
    comment.reportReason = reportReason;
    await comment.save({ validateBeforeSave: false });

    return new ApiResponse(
      StatusCodes.OK,
      "Comment has been reported successfully."
    ).send(res);
  }),

  getCommentById: asyncHandler(async (req, res) => {
    const { id } = req.params;

    const comment = await Comment.findById(id)
      .populate("author", "name avatar")
      .populate("post", "title slug")
      .populate({
        path: "replies",
        populate: { path: "author", select: "name avatar" },
      });

    if (!comment || comment.isDeleted) {
      throw new ApiError(StatusCodes.NOT_FOUND, "Comment not found.");
    }

    return new ApiResponse(
      StatusCodes.OK,
      comment,
      "Comment fetched successfully."
    ).send(res);
  }),

  getCommentsByPost: asyncHandler(async (req, res) => {
    const { postId } = req.params;
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.max(1, parseInt(req.query.limit) || 10);
    const skip = (page - 1) * limit;

    const filter = {
      post: postId,
      parent: null,
      isDeleted: false,
    };

    const totalCount = await Comment.countDocuments(filter);
    const totalPages = Math.ceil(totalCount / limit);

    const comments = await Comment.find(filter)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .populate("author", "name avatar")
      .populate({
        path: "replies",
        match: { isDeleted: false },
        populate: {
          path: "author",
          select: "name avatar",
        },
      });

    return new ApiResponse(
      StatusCodes.OK,
      {
        comments,
        pagination: {
          totalCount,
          currentPage: page,
          totalPages,
          hasNextPage: page < totalPages,
          hasPrevPage: page > 1,
          limit,
        },
      },
      "Comments fetched with pagination."
    ).send(res);
  }),

  getCommentsByUser: asyncHandler(async (req, res) => {
    const { userId } = req.params;
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.max(1, parseInt(req.query.limit) || 10);
    const skip = (page - 1) * limit;

    const filter = {
      author: userId,
      isDeleted: false,
    };

    const totalCount = await Comment.countDocuments(filter);
    const totalPages = Math.ceil(totalCount / limit);

    const comments = await Comment.find(filter)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .populate("post", "title slug")
      .populate("replies", "_id")
      .lean();

    return new ApiResponse(
      StatusCodes.OK,
      {
        comments,
        pagination: {
          totalCount,
          currentPage: page,
          totalPages,
          hasNextPage: page < totalPages,
          hasPrevPage: page > 1,
          limit,
        },
      },
      "User's comments fetched successfully."
    ).send(res);
  }),

  getFlaggedComments: asyncHandler(async (req, res) => {
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.max(1, parseInt(req.query.limit) || 10);
    const skip = (page - 1) * limit;

    const filter = {
      isDeleted: false,
      isReported: true,
    };

    const totalCount = await Comment.countDocuments(filter);
    const totalPages = Math.ceil(totalCount / limit);

    const comments = await Comment.find(filter)
      .sort({ updatedAt: -1 })
      .skip(skip)
      .limit(limit)
      .populate("author", "username email avatar")
      .populate("post", "title slug")
      .lean();

    return new ApiResponse(
      StatusCodes.OK,
      {
        comments,
        pagination: {
          totalCount,
          currentPage: page,
          totalPages,
          hasNextPage: page < totalPages,
          hasPrevPage: page > 1,
          limit,
        },
      },
      "Flagged comments retrieved successfully."
    ).send(res);
  }),

  getRepliesByComment: asyncHandler(async (req, res) => {
    const { commentId } = req.params;

    const page = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.max(1, parseInt(req.query.limit) || 10);
    const skip = (page - 1) * limit;

    const parentComment = await Comment.findById(commentId);
    if (!parentComment || parentComment.isDeleted) {
      throw new ApiError(
        StatusCodes.NOT_FOUND,
        "Parent comment not found or deleted."
      );
    }

    const filter = {
      parent: commentId,
      isDeleted: false,
    };

    const totalCount = await Comment.countDocuments(filter);
    const totalPages = Math.ceil(totalCount / limit);

    const replies = await Comment.find(filter)
      .sort({ createdAt: 1 })
      .skip(skip)
      .limit(limit)
      .populate("author", "username email avatar")
      .lean();

    return new ApiResponse(
      StatusCodes.OK,
      {
        replies,
        parentComment: {
          id: parentComment._id,
          content: parentComment.content,
          author: parentComment.author,
        },
        pagination: {
          totalCount,
          totalPages,
          currentPage: page,
          limit,
          hasNextPage: page < totalPages,
          hasPrevPage: page > 1,
        },
      },
      "Replies fetched successfully."
    ).send(res);
  }),

  getReportedComments: asyncHandler(async (req, res) => {
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.max(1, parseInt(req.query.limit) || 10);
    const skip = (page - 1) * limit;

    const filter = { isReported: true, isDeleted: false };

    const totalCount = await Comment.countDocuments(filter);
    const totalPages = Math.ceil(totalCount / limit);

    const reportedComments = await Comment.find(filter)
      .skip(skip)
      .limit(limit)
      .sort({ createdAt: -1 })
      .populate("author", "username email avatar")
      .lean();

    return new ApiResponse(
      StatusCodes.OK,
      {
        reportedComments,
        pagination: {
          totalCount,
          totalPages,
          currentPage: page,
          limit,
          hasNextPage: page < totalPages,
          hasPrevPage: page > 1,
        },
      },
      "Reported comments fetched successfully."
    ).send(res);
  }),

  likeComment: asyncHandler(async (req, res) => {
    const { commentId } = req.params;
    const userId = req.user._id;

    if (!mongoose.Types.ObjectId.isValid(commentId)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid Id.");
    }

    const comment = await Comment.findById(commentId);
    if (!comment) {
      return new ApiResponse(
        StatusCodes.NOT_FOUND,
        null,
        "Comment not found."
      ).send(res);
    }

    if (comment.likes.includes(userId)) {
      return new ApiResponse(
        StatusCodes.BAD_REQUEST,
        null,
        "You have already liked this comment."
      ).send(res);
    }

    comment.likes.push(userId);

    await comment.save({ validateBeforeSave: false });

    return new ApiResponse(
      StatusCodes.OK,
      comment,
      "Comment liked successfully."
    ).send(res);
  }),

  reportComment: asyncHandler(async (req, res) => {
    const { commentId } = req.params;
    const { reportReason } = req.body;

    if (!mongoose.Types.ObjectId.isValid(commentId)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid Id.");
    }

    if (!reportReason || reportReason.length > 300) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Report reason is required and should not exceed 300 characters."
      );
    }

    const comment = await Comment.findById(commentId);

    if (!comment) {
      throw new ApiError(StatusCodes.NOT_FOUND, "Comment not found.");
    }

    if (comment.isReported) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "This comment has already been reported."
      );
    }

    comment.isReported = true;
    comment.reportReason = reportReason;

    await comment.save({ validateBeforeSave: false });

    return new ApiResponse(
      StatusCodes.OK,
      comment,
      "Comment has been reported successfully."
    ).send(res);
  }),

  restoreDeletedComment: asyncHandler(async (req, res) => {
    const { commentId } = req.params;

    if (!mongoose.Types.ObjectId.isValid(commentId)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid Id.");
    }

    const comment = await Comment.findById(commentId);

    if (!comment) {
      throw new ApiError(StatusCodes.NOT_FOUND, "Comment not found.");
    }

    if (!comment.isDeleted) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Comment is not deleted, so it can't be restored."
      );
    }

    comment.isDeleted = false;
    comment.deletedAt = null;

    await comment.save({ validateBeforeSave: false });

    return new ApiResponse(
      StatusCodes.OK,
      comment,
      "Comment has been restored successfully."
    ).send(res);
  }),

  updateComment: asyncHandler(async (req, res) => {
    const { commentId } = req.params;
    const { content } = req.body;

    if (!mongoose.Types.ObjectId.isValid(commentId)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid Id.");
    }

    const comment = await Comment.findById(commentId);

    if (!comment) {
      throw new ApiError(StatusCodes.NOT_FOUND, "Comment not found.");
    }

    const contentHistoryEntry = {
      content: comment.content,
      updatedAt: new Date(),
      updatedBy: req.user._id,
    };

    comment.contentHistory.push(contentHistoryEntry);

    comment.content = content;

    await comment.save({ validateBeforeSave: false });

    return new ApiResponse(
      StatusCodes.BAD_REQUEST,
      comment,
      "Comment updated successfully."
    ).send(res);
  }),
};

export default CommentController;
