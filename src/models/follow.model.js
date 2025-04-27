import mongoose from "mongoose";

const FollowSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    followedId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    createdAt: {
      type: Date,
      default: Date.now,
    },
  },
  { timestamps: true }
);

FollowSchema.index({ userId: 1, followedId: 1 }, { unique: true });
FollowSchema.index({ followedId: 1 });
FollowSchema.index({ userId: 1 });

const Follow = mongoose.model("Follow", FollowSchema);
export default Follow;
