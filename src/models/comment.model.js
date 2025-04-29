import mongoose from "mongoose";

const commentSchema = new mongoose.Schema(
  {
    // Reference to the user who posted the comment
    postedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    // Reference to the post on which the comment is made
    postId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Post",
      required: true,
    },
    // Content of the comment
    text: {
      type: String,
      required: true,
      trim: true,
      maxlength: 1000,
    },
    // Reference to the parent comment for nested comments
    parentComment: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Comment",
      default: null,
    },
    // Timestamp when the comment was created
    commentedAt: {
      type: Date,
      default: Date.now,
    },
  },
  {
    timestamps: true, // Automatically adds createdAt and updatedAt fields
  }
);

const Comment = mongoose.model("Comment", commentSchema);

export default Comment;
