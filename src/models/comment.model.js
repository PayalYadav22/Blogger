import mongoose from "mongoose";

const commentSchema = new mongoose.Schema(
  {
    /** --------------------- Core Content --------------------- **/
    content: {
      type: String,
      required: [true, "Comment content is required."],
      minlength: [1, "Comment must be at least 1 character long."],
      trim: true,
    },

    /** --------------------- Relationships --------------------- **/
    author: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },
    post: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Post",
      required: true,
      index: true,
    },
    parent: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Comment",
      default: null,
    },
    replies: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: "Comment",
      },
    ],

    /** --------------------- Moderation --------------------- **/
    isApproved: {
      type: Boolean,
      default: false,
      index: true,
    },
    isReported: {
      type: Boolean,
      default: false,
    },
    reportReason: {
      type: String,
      maxlength: 300,
    },

    /** --------------------- Content Management --------------------- **/
    contentHistory: [
      {
        content: String,
        updatedAt: Date,
        updatedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
      },
    ],

    /** --------------------- Engagement --------------------- **/
    likes: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
    dislikes: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],

    /** --------------------- Timestamps --------------------- **/
    isDeleted: {
      type: Boolean,
      default: false,
    },
    deletedAt: {
      type: Date,
      default: null,
    },
  },
  {
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
  }
);

/** --------------------- Middleware --------------------- **/

commentSchema.pre("save", function (next) {
  if (this.isModified("content")) {
    this.updatedAt = Date.now();

    // Push to content history
    if (!this.isNew) {
      this.contentHistory.push({
        content: this.content,
        updatedAt: new Date(),
        updatedBy: this.author,
      });
    }
  }
  if (this.isDeleted && !this.deletedAt) {
    this.deletedAt = Date.now();
  }
  next();
});

/** --------------------- Virtuals --------------------- **/

// Virtual for reply count
commentSchema.virtual("replyCount", {
  ref: "Comment",
  localField: "_id",
  foreignField: "parent",
  count: true,
  match: { isDeleted: false },
});

// Virtual for nested replies (for recursive population)
commentSchema.virtual("nestedReplies", {
  ref: "Comment",
  localField: "_id",
  foreignField: "parent",
  match: { isDeleted: false },
});

/** --------------------- Indexes --------------------- **/
commentSchema.index({ post: 1, parent: 1 });
commentSchema.index({ createdAt: -1 });

const Comment = mongoose.model("Comment", commentSchema);

export default Comment;
