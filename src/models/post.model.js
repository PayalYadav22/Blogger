import mongoose from "mongoose";
import Media from "./media.model.js";
import { generateUniqueSlug, logSlugAudit } from "../utils/slug.helper.js";

// Utility to estimate read time (average 250 words per minute)
const calculateReadTime = (content) => {
  const words = content.split(" ").length;
  return Math.max(1, Math.ceil(words / 250));
};

const postSchema = new mongoose.Schema(
  {
    /** --------------------- Basic Info --------------------- **/
    title: {
      type: String,
      required: [true, "Post title is required."],
      trim: true,
      minlength: [3, "Title must be at least 3 characters."],
      maxlength: [150, "Title cannot exceed 150 characters."],
      set: (v) => v.trim(),
    },
    slug: {
      type: String,
      unique: true,
      lowercase: true,
      trim: true,
      index: true,
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
      url: {
        type: String,
        match: [/^https?:\/\/.+\..+/, "Invalid URL format for banner image."],
      },
      publicId: { type: String },
    },
    coverImageAltText: {
      type: String,
      maxlength: 200,
      default: "",
    },

    /** --------------------- Author & Tags --------------------- **/
    author: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      immutable: true,
    },
    tags: {
      type: [String],
      lowercase: true,
      trim: true,
      validate: [
        {
          validator: (arr) => arr.length <= 5,
          message: "Maximum of 5 tags allowed.",
        },
      ],
    },
    categories: {
      type: [String],
      lowercase: true,
      trim: true,
      validate: [
        {
          validator: (arr) => arr.length <= 5,
          message: "Maximum of 5 categories allowed.",
        },
      ],
    },

    /** --------------------- Publication --------------------- **/
    isPublished: { type: Boolean, default: false },
    publishedAt: { type: Date, default: null },
    isFeatured: { type: Boolean, default: false },

    /** --------------------- SEO Metadata --------------------- **/
    meta: {
      title: {
        type: String,
        maxlength: 70,
        trim: true,
        default: function () {
          return this.title || "Default Title";
        },
      },
      description: {
        type: String,
        maxlength: 160,
        trim: true,
        default: function () {
          return this.content.slice(0, 160);
        },
      },
    },

    /** --------------------- Versioning & Read Time --------------------- **/
    draftVersion: { type: Number, default: 1 },
    readTime: { type: Number, default: 0 },

    /** --------------------- Collaboration --------------------- **/
    collaborators: [
      {
        user: {
          type: mongoose.Schema.Types.ObjectId,
          ref: "User",
          required: true,
        },
        role: {
          type: String,
          enum: ["author", "editor", "viewer"],
          required: true,
        },
        permissions: {
          type: [String],
          enum: ["read", "write", "delete"],
          validate: {
            validator: (arr) => arr.length > 0 && arr.length <= 3,
            message: "Permissions must include 1 to 3 valid values.",
          },
          default: ["read"],
        },
      },
    ],

    /** --------------------- Media & History --------------------- **/
    media: [{ type: mongoose.Schema.Types.ObjectId, ref: "Media" }],
    contentHistory: [
      {
        content: String,
        updatedAt: Date,
        updatedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
      },
    ],

    /** --------------------- Engagement Tracking --------------------- **/
    views: { type: Number, default: 0 },
    viewedBy: [
      {
        ip: {
          type: String,
          match: [/^(?:\d{1,3}\.){3}\d{1,3}$/, "Invalid IP address."],
        },
        viewedAt: { type: Date, default: Date.now },
      },
    ],

    /** --------------------- Approval Workflow --------------------- **/
    needsApproval: { type: Boolean, default: true },
    approvedAt: { type: Date, select: false },
    approvedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      select: false,
    },

    /** --------------------- Soft Delete --------------------- **/
    isDeleted: { type: Boolean, default: false },
  },
  {
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
  }
);

/** --------------------- Indexes --------------------- **/
postSchema.index({ author: 1 });
postSchema.index({ isPublished: 1 });
postSchema.index({ createdAt: -1 });
postSchema.index({ author: 1, isPublished: 1 });
postSchema.index({ title: "text", content: "text", tags: "text" }); // Full-text search

/** --------------------- Middleware --------------------- **/
postSchema.pre("save", async function (next) {
  // Auto-generate excerpt if missing
  if (!this.excerpt && this.content) {
    let excerpt = this.content.slice(0, 500);
    const lastPeriod = excerpt.lastIndexOf(".");
    if (lastPeriod !== -1) {
      excerpt = excerpt.slice(0, lastPeriod + 1);
    }
    this.excerpt = excerpt || this.content.slice(0, 500);
  }

  // If title hasn't changed, skip slug generation
  if (!this.isModified("title")) return next();

  const oldSlug = this.slug;
  const newSlug = await generateUniqueSlug(this.title, this._id);
  this.slug = newSlug;
  await logSlugAudit(this._id, oldSlug, newSlug);

  // Ensure meta.title fallback
  if (!this.meta.title) {
    this.meta.title = this.title || "Default Title";
  }

  // Estimate reading time
  this.readTime = calculateReadTime(this.content);

  // Set publish time if just published
  if (this.isPublished && !this.publishedAt) {
    this.publishedAt = new Date();
  }

  next();
});

postSchema.pre("findOneAndUpdate", async function (next) {
  const update = this.getUpdate();
  if (update?.title) {
    const post = await this.model.findOne(this.getQuery());
    if (post && post.title !== update.title) {
      const newSlug = await generateUniqueSlug(update.title, post._id);
      update.slug = newSlug;
    }
  }
  next();
});

/** --------------------- Virtual Fields --------------------- **/
postSchema.virtual("likesCount", {
  ref: "BlogLike",
  localField: "_id",
  foreignField: "post",
  count: true,
});

postSchema.virtual("comments", {
  ref: "Comment",
  localField: "_id",
  foreignField: "post",
  match: { isDeleted: false, parent: null },
  options: { sort: { createdAt: -1 } },
});

postSchema.virtual("approvedCommentsCount", {
  ref: "Comment",
  localField: "_id",
  foreignField: "post",
  match: { isApproved: true, isDeleted: false },
  count: true,
});

/** --------------------- Static Methods --------------------- **/
postSchema.statics.getPublishedPosts = function () {
  return this.find({ isPublished: true, isDeleted: false }).sort({
    createdAt: -1,
  });
};

const Post = mongoose.model("Post", postSchema);
export default Post;
