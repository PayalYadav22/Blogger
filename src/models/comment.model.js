import mongoose from "mongoose";

const commentSchema = new mongoose.Schema(
  {
    content: {
      type: String,
      required: [true, "Comment content is required."],
      minlength: [1, "Comment must be at least 1 character long."],
    },
    author: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    post: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Post",
      required: true,
    },
    parent: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Comment", // This references the parent comment for nested replies
      default: null,
    },
    isApproved: {
      type: Boolean,
      default: false, // New comments need approval
    },
    isReported: {
      type: Boolean,
      default: false, // Flagged for moderation
    },
    isDeleted: {
      type: Boolean,
      default: false, // Marked as deleted without removal
    },
    replies: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: "Comment", // Nested replies
      },
    ],
    createdAt: {
      type: Date,
      default: Date.now,
    },
    updatedAt: {
      type: Date,
      default: Date.now,
    },
  },
  {
    timestamps: true,
  }
);

// Automatically update `updatedAt` field when the comment is modified
commentSchema.pre("save", function (next) {
  if (this.isModified("content")) {
    this.updatedAt = Date.now();
  }
  next();
});

const Comment = mongoose.model("Comment", commentSchema);

export default Comment;
