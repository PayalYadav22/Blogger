import mongoose from "mongoose";

const mediaSchema = new mongoose.Schema(
  {
    // Media type - image, video, or audio
    type: {
      type: String,
      enum: ["image", "video", "audio"],
      required: true,
    },

    // The URL where the media is stored (could be Cloudinary, S3, etc.)
    url: {
      type: String,
      required: true,
    },

    // A thumbnail URL for quick preview
    thumbnailUrl: {
      type: String,
    },

    // Caption for the media
    caption: {
      type: String,
      maxlength: 500, // Limit the caption length
    },

    // Duration of the media, applicable for videos/audio
    duration: {
      type: Number,
    },

    // Format of the media (e.g., jpg, mp4, mp3)
    format: {
      type: String,
    },

    // Size of the file in bytes
    size: {
      type: Number,
      required: true,
    },

    // The timestamp when the media was uploaded
    uploadedAt: {
      type: Date,
      default: Date.now,
    },

    // Metadata for images/videos/audio
    metadata: {
      width: Number, // For images
      height: Number, // For images
      resolution: String, // For images (e.g., 1920x1080)
      bitrate: Number, // For audio
      codec: String, // For audio/video
      fps: Number, // For video frames per second
      audioChannels: Number, // For audio (e.g., mono, stereo)
    },

    // Tags to classify and search media
    tags: {
      type: [String],
      index: true, // Making tags searchable
    },

    // Media status - Pending, Approved, or Rejected
    status: {
      type: String,
      enum: ["pending", "approved", "rejected"],
      default: "pending",
    },

    // Versioning for media updates (e.g., replacing an old video)
    version: {
      type: Number,
      default: 1,
    },

    // The user who uploaded the media
    uploadedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User", // Assuming you have a User model
      required: true,
    },

    // Access control: public or private
    accessControl: {
      type: String,
      enum: ["public", "private", "restricted"],
      default: "public",
    },

    // Expiry date for media (optional, for time-limited media)
    expiresAt: {
      type: Date,
      default: null, // If null, media does not expire
    },

    // Watermark URL, for images or videos
    watermarkUrl: {
      type: String,
      default: null, // Optional
    },

    // Processing status (e.g., transcoding)
    processingStatus: {
      type: String,
      enum: ["pending", "processing", "completed"],
      default: "pending",
    },

    // Logs for each operation on the media (e.g., if it's edited, watermarked, etc.)
    operationLogs: [
      {
        action: {
          type: String,
          required: true, // E.g., 'watermarking', 'transcoding', 'update'
          enum: ["watermarking", "transcoding", "update", "delete"], // Define allowed actions
        },
        timestamp: {
          type: Date,
          default: Date.now,
        },
        user: {
          type: mongoose.Schema.Types.ObjectId,
          ref: "User", // If available, track who performed the action
        },
      },
    ],

    // Soft delete (optional, in case you want to mark media as deleted instead of actually deleting it)
    isDeleted: {
      type: Boolean,
      default: false,
    },

    // Support for comments or ratings on media
    comments: [
      {
        user: {
          type: mongoose.Schema.Types.ObjectId,
          ref: "User",
        },
        content: String,
        timestamp: { type: Date, default: Date.now },
      },
    ],

    // Rating system for media (e.g., user ratings)
    rating: {
      type: Number,
      min: 0,
      max: 5,
      default: 0,
    },
  },
  {
    timestamps: true,
  }
);

// Adding virtuals for computed fields, such as `isExpired`
mediaSchema.virtual("isExpired").get(function () {
  return this.expiresAt && new Date() > this.expiresAt;
});

// Adding pre-save hooks to update version on replacement of media
mediaSchema.pre("save", function (next) {
  if (this.isNew) {
    this.version = 1;
  }
  next();
});

const Media = mongoose.model("Media", mediaSchema);

export default Media;
