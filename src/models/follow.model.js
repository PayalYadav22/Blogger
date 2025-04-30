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
    isDeleted: {
      type: Boolean,
      default: false,
    },
  },
  { timestamps: true }
);

// Prevent following oneself
FollowSchema.pre("save", function (next) {
  if (this.userId.equals(this.followedId)) {
    next(new Error("A user cannot follow themselves."));
  } else {
    next();
  }
});

// Indexes
FollowSchema.index({ userId: 1, followedId: 1 }, { unique: true });
FollowSchema.index({ followedId: 1 });
FollowSchema.index({ userId: 1 });

// Add a method to toggle follow/unfollow
FollowSchema.methods.toggleFollow = async function () {
  const existingFollow = await Follow.findOne({
    userId: this.userId,
    followedId: this.followedId,
  });

  if (existingFollow) {
    await existingFollow.remove();
  } else {
    await this.save();
  }
};

const Follow = mongoose.model("Follow", FollowSchema);
export default Follow;
