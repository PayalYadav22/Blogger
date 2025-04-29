import mongoose from "mongoose";

const LikeSchema = new mongoose.Schema(
  {
    post: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Post",
      required: true,
    },
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    likedAt: {
      type: Date,
      default: Date.now,
    },
  },
  {
    timestamps: true, // adds createdAt and updatedAt fields automatically
  }
);

// Ensure that a user can like a post only once
LikeSchema.index({ post: 1, user: 1 }, { unique: true });

const Like = mongoose.model("Like", LikeSchema);

export default Like;
