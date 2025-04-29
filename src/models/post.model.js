import mongoose from "mongoose";
import slugify from "slugify";

const postSchema = new mongoose.Schema(
  {
    title: {
      type: String,
      required: [true, "Post title is required."],
      trim: true,
      minlength: [3, "Title must be at least 3 characters long."],
      maxlength: [150, "Title cannot exceed 150 characters."],
    },
    slug: {
      type: String,
      unique: true,
      lowercase: true,
      trim: true,
    },
    content: {
      type: String,
      required: [true, "Post content is required."],
    },
    excerpt: {
      type: String,
      maxlength: 500,
      default: "",
    },
    bannerImage: {
      url: { type: String },
      publicId: { type: String },
    },
    author: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    tags: [
      {
        type: String,
        lowercase: true,
        trim: true,
      },
    ],
    categories: [
      {
        type: String,
        lowercase: true,
        trim: true,
      },
    ],
    isPublished: {
      type: Boolean,
      default: false,
    },
    publishedAt: {
      type: Date,
    },
    isFeatured: {
      type: Boolean,
      default: false,
    },
    meta: {
      title: {
        type: String,
        maxlength: 70,
        trim: true,
        required: true,
        unique: true,
      },
      description: {
        type: String,
        maxlength: 160,
        trim: true,
        required: true,
      },
    },
    views: {
      type: Number,
      default: 0,
    },
    needsApproval: {
      type: Boolean,
      default: true,
    },
    approvedAt: {
      type: Date,
      select: false,
    },
    approvedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      select: false,
    },
  },
  {
    timestamps: true, // adds createdAt and updatedAt automatically
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
  }
);

// Auto-generate slug before saving
postSchema.pre("save", function (next) {
  if (this.isModified("title")) {
    this.slug = slugify(this.title, { lower: true, strict: true });
  }
  next();
});

// Virtual field for like count (assuming you have BlogLike model)
postSchema.virtual("likesCount", {
  ref: "BlogLike",
  localField: "_id",
  foreignField: "post",
  count: true,
});

// Virtual field for comments (example)
postSchema.virtual("comments", {
  ref: "Comment",
  localField: "_id",
  foreignField: "post",
});

const Post = mongoose.model("Post", postSchema);

export default Post;
