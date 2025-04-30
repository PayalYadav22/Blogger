import asyncHandler from "../../middleware/asyncHandler.middleware.js";
import Media from "../../models/media.model.js";
import {
  uploadFileToCloudinary,
  deleteFileFromCloudinary,
} from "../../config/cloudinary.config.js";

const MediaController = {
  createMedia: asyncHandler(async (req, res) => {
    const {
      type,
      url,
      thumbnailUrl,
      caption,
      duration,
      format,
      size,
      metadata,
      tags,
      status,
      accessControl,
      expiresAt,
      watermarkUrl,
      processingStatus,
    } = req.body;

    const uploadedBy = req.user?._id;

    if (!type || !url || !size || !uploadedBy) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Required fields missing.");
    }

    const allowedTypes = ["image", "video", "audio"];

    if (!allowedTypes.includes(type)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid media type.");
    }

    if (type === "video" || type === "audio") {
      const mediaValidationResult = await validateMedia(url);

      if (
        mediaValidationResult !== "Valid video" &&
        mediaValidationResult !== "Valid audio"
      ) {
        throw new ApiError(StatusCodes.BAD_REQUEST, mediaValidationResult);
      }
    }

    let cloudinaryUrl = url;
    if (type === "image" || type === "video") {
      const localFilePath = req.file.path;
      const cloudinaryResponse = await uploadFileToCloudinary(localFilePath);

      if (!cloudinaryResponse) {
        throw new ApiError(
          StatusCodes.INTERNAL_SERVER_ERROR,
          "Cloudinary upload failed."
        );
      }
      cloudinaryUrl = cloudinaryResponse.secure_url;
    }

    const media = await Media.create({
      type,
      url: cloudinaryUrl,
      thumbnailUrl,
      caption,
      duration,
      format,
      size,
      metadata,
      tags,
      status,
      accessControl,
      expiresAt,
      watermarkUrl,
      processingStatus,
      uploadedBy,
    });

    return new ApiResponse(
      StatusCodes.OK,
      {
        id: media._id,
        type: media.type,
        url: media.url,
        thumbnailUrl: media.thumbnailUrl,
        caption: media.caption,
        duration: media.duration,
        format: media.format,
        size: media.size,
        metadata: media.metadata,
        tags: media.tags,
        status: media.status,
        accessControl: media.accessControl,
        expiresAt: media.expiresAt,
        watermarkUrl: media.watermarkUrl,
        processingStatus: media.processingStatus,
        uploadedBy: media.uploadedBy,
      },
      "Media created successfully"
    ).send(res);
  }),

  getAllMedia: asyncHandler(async (req, res) => {
    const {
      type,
      status,
      tags,
      page = 1,
      limit = 10,
      sortBy = "uploadedAt",
      sortOrder = "desc",
    } = req.query;

    const query = {};

    if (type) {
      query.type = type;
    }

    if (status) {
      query.status = status;
    }

    if (tags) {
      query.tags = { $in: tags.split(",") };
    }

    query.isDeleted = { $ne: true };

    const skip = (page - 1) * limit;
    const limitResults = parseInt(limit, 10);

    const sort = {};
    sort[sortBy] = sortOrder === "desc" ? -1 : 1;

    const media = await Media.find(query)
      .skip(skip)
      .limit(limitResults)
      .sort(sort)
      .exec();

    const totalMedia = await Media.countDocuments(query);

    const totalPages = Math.ceil(totalMedia / limitResults);

    return new ApiResponse(
      StatusCodes.OK,
      {
        id: media._id,
        type: media.type,
        url: media.url,
        thumbnailUrl: media.thumbnailUrl,
        caption: media.caption,
        duration: media.duration,
        format: media.format,
        size: media.size,
        metadata: media.metadata,
        tags: media.tags,
        status: media.status,
        accessControl: media.accessControl,
        expiresAt: media.expiresAt,
        watermarkUrl: media.watermarkUrl,
        processingStatus: media.processingStatus,
        uploadedBy: media.uploadedBy,
        pagination: {
          currentPage: page,
          totalPages,
          totalItems: totalMedia,
          itemsPerPage: limitResults,
        },
      },
      "Media fetched successfully"
    ).send(res);
  }),

  getSingleMedia: asyncHandler(async (req, res) => {
    const { mediaId } = req.params;

    if (!mongoose.Types.ObjectId.isValid(mediaId)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid media ID.");
    }

    const media = await Media.findOne({ _id: mediaId, isDeleted: false })
      .populate("uploadedBy", "name username avatar")
      .lean();

    if (!media) {
      throw new ApiError(StatusCodes.NOT_FOUND, "Media not found.");
    }

    return new ApiResponse(
      StatusCodes.OK,
      {
        id: media._id,
        type: media.type,
        url: media.url,
        thumbnailUrl: media.thumbnailUrl,
        caption: media.caption,
        duration: media.duration,
        format: media.format,
        size: media.size,
        metadata: media.metadata,
        tags: media.tags,
        status: media.status,
        accessControl: media.accessControl,
        expiresAt: media.expiresAt,
        watermarkUrl: media.watermarkUrl,
        processingStatus: media.processingStatus,
        uploadedBy: media.uploadedBy,
        comments: media.comments,
        rating: media.rating,
        operationLogs: media.operationLogs,
      },
      "Media fetched successfully"
    ).send(res);
  }),

  updateMedia: asyncHandler(async (req, res) => {
    const { mediaId } = req.params;

    const { caption, tags, status, accessControl, expiresAt } = req.body;

    if (!mongoose.Types.ObjectId.isValid(mediaId)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid media ID.");
    }

    const media = await Media.findOne({ _id: mediaId, isDeleted: false });

    if (!media) {
      throw new ApiError(StatusCodes.NOT_FOUND, "Media not found.");
    }

    let updatedUrl, updatedThumbnailUrl, updatedWatermarkUrl;

    const uploader = await uploadFileToCloudinary(req.files.file.path);

    updatedUrl = uploader.secure_url;
    updatedThumbnailUrl = uploader.thumbnail_url || null;
    updatedWatermarkUrl = uploader.secure_url;

    media.caption = caption || media.caption;
    media.tags = tags || media.tags;
    media.status = status || media.status;
    media.accessControl = accessControl || media.accessControl;
    media.expiresAt = expiresAt || media.expiresAt;
    if (updatedUrl) {
      media.url = updatedUrl;
    }
    if (updatedThumbnailUrl) {
      media.thumbnailUrl = updatedThumbnailUrl;
    }
    if (updatedWatermarkUrl) {
      media.watermarkUrl = updatedWatermarkUrl;
    }

    media.version += 1;

    media.operationLogs.push({
      action: "update",
      user: req.user._id,
    });

    await media.save({ validateBeforeSave: false });

    return new ApiResponse(
      StatusCodes.OK,
      {
        id: media._id,
        type: media.type,
        url: media.url,
        thumbnailUrl: media.thumbnailUrl,
        caption: media.caption,
        duration: media.duration,
        format: media.format,
        size: media.size,
        metadata: media.metadata,
        tags: media.tags,
        status: media.status,
        accessControl: media.accessControl,
        expiresAt: media.expiresAt,
        watermarkUrl: media.watermarkUrl,
        processingStatus: media.processingStatus,
        uploadedBy: media.uploadedBy,
        operationLogs: media.operationLogs,
      },
      "Media updated successfully"
    ).send(res);
  }),

  deleteMedia: asyncHandler(async (req, res) => {
    const { mediaId } = req.params;

    if (!mongoose.Types.ObjectId.isValid(mediaId)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid media ID.");
    }

    const media = await Media.findOne({ _id: mediaId, isDeleted: false });

    if (!media) {
      throw new ApiError(StatusCodes.NOT_FOUND, "Media not found.");
    }

    if (media.url) {
      const publicId = media.url.split("/").pop().split(".")[0];
      try {
        await deleteFileFromCloudinary(publicId);
      } catch (error) {
        throw new ApiError(
          StatusCodes.INTERNAL_SERVER_ERROR,
          "Error deleting file from Cloudinary."
        );
      }
    }

    media.operationLogs.push({
      action: "delete",
      user: req.user._id,
    });

    media.isDeleted = true;
    await media.save({ validateBeforeSave: false });

    return new ApiResponse(StatusCodes.OK, "Media deleted successfully").send(
      res
    );
  }),

  approveMedia: asyncHandler(async (req, res) => {
    const { mediaId } = req.params;

    if (!mongoose.Types.ObjectId.isValid(mediaId)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid media ID.");
    }

    const media = await Media.findOne({ _id: mediaId, isDeleted: false });

    if (!media) {
      throw new ApiError(StatusCodes.NOT_FOUND, "Media not found.");
    }

    if (media.status === "approved") {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Media is already approved.");
    }

    if (media.status === "rejected") {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Media is rejected and cannot be approved."
      );
    }

    media.status = "approved";

    media.operationLogs.push({
      action: "approve",
      user: req.user._id,
    });

    await media.save({ validateBeforeSave: false });

    return new ApiResponse(
      StatusCodes.OK,
      {
        id: media._id,
        type: media.type,
        url: media.url,
        thumbnailUrl: media.thumbnailUrl,
        caption: media.caption,
        duration: media.duration,
        format: media.format,
        size: media.size,
        metadata: media.metadata,
        tags: media.tags,
        status: media.status,
        accessControl: media.accessControl,
        expiresAt: media.expiresAt,
        watermarkUrl: media.watermarkUrl,
        processingStatus: media.processingStatus,
        uploadedBy: media.uploadedBy,
      },
      "Media approved successfully."
    );
  }),

  rejectMedia: asyncHandler(async (req, res) => {
    const { mediaId } = req.params;

    if (!mongoose.Types.ObjectId.isValid(mediaId)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid media ID.");
    }

    const media = await Media.findOne({ _id: mediaId, isDeleted: false });

    if (!media) {
      throw new ApiError(StatusCodes.NOT_FOUND, "Media not found.");
    }

    if (media.status === "approved") {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Approved media cannot be rejected."
      );
    }

    if (media.status === "rejected") {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Media is already rejected.");
    }

    media.status = "rejected";

    media.operationLogs.push({
      action: "reject",
      user: req.user._id,
    });

    await media.save({ validateBeforeSave: false });

    return new ApiResponse(StatusCodes.OK, "Media rejected successfully.").send(
      res
    );
  }),

  setMediaToPending: asyncHandler(async (req, res) => {
    const { mediaId } = req.params;
    const userId = req.user?._id;

    if (!mongoose.Types.ObjectId.isValid(mediaId)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid media ID.");
    }

    const media = await Media.findById(mediaId);

    if (!media || media.isDeleted) {
      return new ApiError(
        StatusCodes.NOT_FOUND,
        "Media not found or already deleted."
      );
    }

    if (media.status === "pending") {
      return new ApiError(
        StatusCodes.NOT_FOUND,
        "Media is already in pending state."
      );
    }

    media.status = "pending";

    media.operationLogs.push({
      action: "update",
      user: userId,
    });

    await media.save({ validateBeforeSave: false });

    return new ApiResponse(
      StatusCodes.OK,
      {
        id: media._id,
        type: media.type,
        url: media.url,
        thumbnailUrl: media.thumbnailUrl,
        caption: media.caption,
        duration: media.duration,
        format: media.format,
        size: media.size,
        metadata: media.metadata,
        tags: media.tags,
        status: media.status,
        accessControl: media.accessControl,
        expiresAt: media.expiresAt,
        watermarkUrl: media.watermarkUrl,
        processingStatus: media.processingStatus,
        uploadedBy: media.uploadedBy,
        comments: media.comments,
        rating: media.rating,
        operationLogs: media.operationLogs,
      },
      "Media status set to pending successfully"
    ).send(res);
  }),

  startProcessingMedia: asyncHandler(async (req, res) => {
    const { mediaId } = req.params;
    const userId = req.user?._id;

    if (!mongoose.Types.ObjectId.isValid(mediaId)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid media ID.");
    }

    const media = await Media.findById(mediaId);

    if (!media || media.isDeleted) {
      throw new ApiError(
        StatusCodes.NOT_FOUND,
        "Media not found or has been deleted."
      );
    }

    if (media.processingStatus === "processing") {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Media is already processing."
      );
    }

    if (media.processingStatus === "completed") {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Media processing is already completed."
      );
    }

    media.processingStatus = "processing";

    media.operationLogs.push({
      action: "transcoding",
      user: userId,
    });

    await media.save({ validateBeforeSave: false });

    return new ApiResponse(
      StatusCodes.OK,
      {
        id: media._id,
        type: media.type,
        url: media.url,
        thumbnailUrl: media.thumbnailUrl,
        caption: media.caption,
        duration: media.duration,
        format: media.format,
        size: media.size,
        metadata: media.metadata,
        tags: media.tags,
        status: media.status,
        accessControl: media.accessControl,
        expiresAt: media.expiresAt,
        watermarkUrl: media.watermarkUrl,
        processingStatus: media.processingStatus,
        uploadedBy: media.uploadedBy,
        comments: media.comments,
        rating: media.rating,
        operationLogs: media.operationLogs,
      },
      "Media processing started."
    ).send(res);
  }),

  completeProcessingMedia: asyncHandler(async (req, res) => {
    const { mediaId } = req.params;
    const userId = req.user?._id;

    if (!mongoose.Types.ObjectId.isValid(mediaId)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid media ID.");
    }

    const media = await Media.findById(mediaId);

    if (!media || media.isDeleted) {
      throw new ApiError(
        StatusCodes.NOT_FOUND,
        "Media not found or has been deleted."
      );
    }

    if (media.processingStatus !== "processing") {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Cannot complete processing — media is not in processing state."
      );
    }

    media.processingStatus = "completed";

    media.operationLogs.push({
      action: "transcoding",
      user: userId,
    });

    await media.save({ validateBeforeSave: false });

    return new ApiResponse(
      StatusCodes.OK,
      {
        id: media._id,
        type: media.type,
        url: media.url,
        thumbnailUrl: media.thumbnailUrl,
        caption: media.caption,
        duration: media.duration,
        format: media.format,
        size: media.size,
        metadata: media.metadata,
        tags: media.tags,
        status: media.status,
        accessControl: media.accessControl,
        expiresAt: media.expiresAt,
        watermarkUrl: media.watermarkUrl,
        processingStatus: media.processingStatus,
        uploadedBy: media.uploadedBy,
        comments: media.comments,
        rating: media.rating,
        operationLogs: media.operationLogs,
      },
      "Media processing marked as completed."
    ).send(res);
  }),

  logMediaOperation: asyncHandler(async (req, res) => {
    const { mediaId } = req.params;
    const userId = req.user?._id;

    if (!mongoose.Types.ObjectId.isValid(mediaId)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid media ID.");
    }

    const validActions = ["watermarking", "transcoding", "update", "delete"];

    if (!validActions.includes(action)) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        `Invalid action. Allowed actions are: ${validActions.join(", ")}`
      );
    }

    const media = await Media.findById(id);

    if (!media || media.isDeleted) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Media not found or has been deleted"
      );
    }

    media.operationLogs.push({
      action,
      user: userId,
    });

    await media.save({ validateBeforeSave: false });

    return new ApiResponse(
      StatusCodes.OK,
      {
        id: media._id,
        type: media.type,
        url: media.url,
        thumbnailUrl: media.thumbnailUrl,
        caption: media.caption,
        duration: media.duration,
        format: media.format,
        size: media.size,
        metadata: media.metadata,
        tags: media.tags,
        status: media.status,
        accessControl: media.accessControl,
        expiresAt: media.expiresAt,
        watermarkUrl: media.watermarkUrl,
        processingStatus: media.processingStatus,
        uploadedBy: media.uploadedBy,
        comments: media.comments,
        rating: media.rating,
        operationLogs: media.operationLogs,
      },
      `Operation '${action}' logged successfully`
    ).send(res);
  }),

  changeAccessControl: asyncHandler(async (req, res) => {
    const { mediaId } = req.params;
    const userId = req.user?._id;

    if (!mongoose.Types.ObjectId.isValid(mediaId)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid media ID.");
    }

    const allowedValues = ["public", "private", "restricted"];

    if (!allowedValues.includes(accessControl)) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Invalid access control. Allowed values: public, private, restricted"
      );
    }

    const media = await Media.findById(id);

    if (!media || media.isDeleted) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Media not found or has been deleted"
      );
    }

    if (!media.uploadedBy.equals(userId) && req.user.role !== "admin") {
      throw new ApiError(
        StatusCodes.FORBIDDEN,
        "Not authorized to change access control."
      );
    }

    media.accessControl = accessControl;

    media.operationLogs.push({
      action: "update",
      user: userId,
    });

    await media.save({ validateBeforeSave: false });

    return new ApiResponse(
      StatusCodes.OK,
      {
        id: media._id,
        type: media.type,
        url: media.url,
        thumbnailUrl: media.thumbnailUrl,
        caption: media.caption,
        duration: media.duration,
        format: media.format,
        size: media.size,
        metadata: media.metadata,
        tags: media.tags,
        status: media.status,
        accessControl: media.accessControl,
        expiresAt: media.expiresAt,
        watermarkUrl: media.watermarkUrl,
        processingStatus: media.processingStatus,
        uploadedBy: media.uploadedBy,
        comments: media.comments,
        rating: media.rating,
        operationLogs: media.operationLogs,
      },
      `Access control updated to '${accessControl}'`
    ).send(res);
  }),

  setMediaExpiry: asyncHandler(async (req, res) => {
    const { mediaId } = req.params;
    const { expiresAt } = req.body;
    const userId = req.user?._id;

    if (!mongoose.Types.ObjectId.isValid(mediaId)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid media ID.");
    }

    if (!expiresAt || isNaN(new Date(expiresAt))) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Invalid or missing expiry date ."
      );
    }

    const expiryDate = new Date(expiresAt);

    if (expiryDate < new Date()) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Expiry date must be in the future ."
      );
    }

    const media = await Media.findById(mediaId);

    if (!media || media.isDeleted) {
      throw new ApiError(
        StatusCodes.NOT_FOUND,
        "Media not found or already deleted."
      );
    }

    if (!media.uploadedBy.equals(userId) && req.user.role !== "admin") {
      throw new ApiError(
        StatusCodes.FORBIDDEN,
        "Not authorized to set media expiry."
      );
    }

    media.expiresAt = expiryDate;

    media.operationLogs.push({
      action: "update",
      user: userId,
    });

    await media.save({ validateBeforeSave: false });

    return new ApiResponse(
      StatusCodes.OK,
      {
        expiresAt: media.expiresAt,
      },
      "Media expiry date updated successfully"
    ).send(res);
  }),

  addComment: asyncHandler(async (req, res) => {
    const { mediaId } = req.params;
    const { content } = req.body;
    const userId = req.user?._id;

    if (!mongoose.Types.ObjectId.isValid(mediaId)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid media ID.");
    }

    if (!content) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Comment content is required."
      );
    }

    const media = await Media.findById(mediaId);

    if (!media || media.isDeleted) {
      throw new ApiError(StatusCodes.NOT_FOUND, "Media not found .");
    }

    media.comments.push({
      user: userId,
      content,
    });

    await media.save({ validateBeforeSave: false });

    return new ApiResponse(
      StatusCodes.OK,
      {
        comments: media.comments,
      },
      "Comment added successfully"
    ).send(res);
  }),

  getComments: asyncHandler(async (req, res) => {
    const { mediaId } = req.params;

    if (!mongoose.Types.ObjectId.isValid(mediaId)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid media ID.");
    }

    const media = await Media.findById(mediaId)
      .populate("comments.user", "userName avatar")
      .select("comments");

    if (!media) {
      throw new ApiError(StatusCodes.NOT_FOUND, "Media not found.");
    }

    return new ApiResponse(
      StatusCodes.OK,
      { comments: media.comments },
      "Successfully fetched comments for the media."
    ).send(res);
  }),

  addRating: asyncHandler(async (req, res) => {
    const { mediaId } = req.params;
    const { rating } = req.body;

    if (!mongoose.Types.ObjectId.isValid(mediaId)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid media ID.");
    }

    if (rating < 0 || rating > 5) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Rating must be between 0 and 5."
      );
    }

    const media = await Media.findById(mediaId);

    if (!media) {
      throw new ApiError(StatusCodes.NOT_FOUND, "Media not found.");
    }

    media.rating = rating;

    await media.save({ validateBeforeSave: false });

    return new ApiResponse(
      StatusCodes.OK,
      { rating: media.rating },
      "Rating successfully updated."
    ).send(res);
  }),

  searchMediaByTags: asyncHandler(async (req, res) => {
    const { tags } = req.query;

    if (!tags) {
      return res
        .status(400)
        .json({ message: "Tags query parameter is required." });
    }

    const tagArray = tags.split(",").map((tag) => tag.trim());

    const media = await Media.find({
      tags: { $in: tagArray },
      isDeleted: false,
      accessControl: "public",
    })
      .sort({ createdAt: -1 })
      .select("-__v");

    return new ApiResponse(
      StatusCodes.OK,
      {
        media: media.map((item) => ({
          id: item._id,
          type: item.type,
          url: item.url,
          thumbnailUrl: item.thumbnailUrl,
          caption: item.caption,
          duration: item.duration,
          format: item.format,
          size: item.size,
          metadata: item.metadata,
          tags: item.tags,
          status: item.status,
          accessControl: item.accessControl,
          expiresAt: item.expiresAt,
          watermarkUrl: item.watermarkUrl,
          processingStatus: item.processingStatus,
          uploadedBy: item.uploadedBy,
          comments: item.comments,
          rating: item.rating,
          operationLogs: item.operationLogs,
        })),
        count: media.length,
      },
      "Media fetched successfully."
    ).send(res);
  }),

  filterMediaByType: asyncHandler(async (req, res) => {
    const { type } = req.query;

    if (!type || !["image", "video", "audio"].includes(type)) {
      return res.status(StatusCodes.BAD_REQUEST).json({
        success: false,
        message:
          "Invalid or missing 'type'. Allowed values: image, video, audio.",
      });
    }

    const mediaList = await Media.find({
      type,
      isDeleted: false,
    }).sort({ createdAt: -1 });

    return new ApiResponse(
      StatusCodes.OK,
      {
        media: mediaList.map((media) => ({
          id: media._id,
          type: media.type,
          url: media.url,
          thumbnailUrl: media.thumbnailUrl,
          caption: media.caption,
          duration: media.duration,
          format: media.format,
          size: media.size,
          metadata: media.metadata,
          tags: media.tags,
          status: media.status,
          accessControl: media.accessControl,
          expiresAt: media.expiresAt,
          watermarkUrl: media.watermarkUrl,
          processingStatus: media.processingStatus,
          uploadedBy: media.uploadedBy,
          comments: media.comments,
          rating: media.rating,
          operationLogs: media.operationLogs,
        })),
        count: mediaList.length,
      },
      `Media filtered by type '${type}' retrieved successfully.`
    ).send(res);
  }),

  filterMediaByStatus: asyncHandler(async (req, res) => {
    const { status } = req.query;

    if (!status || !["pending", "approved", "rejected"].includes(status)) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Invalid or missing 'status'. Allowed values: pending, approved, rejected."
      );
    }

    const mediaList = await Media.find({
      status,
      isDeleted: false,
    }).sort({ createdAt: -1 });

    return new ApiResponse(
      StatusCodes.OK,
      {
        media: mediaList.map((media) => ({
          id: media._id,
          type: media.type,
          url: media.url,
          thumbnailUrl: media.thumbnailUrl,
          caption: media.caption,
          duration: media.duration,
          format: media.format,
          size: media.size,
          metadata: media.metadata,
          tags: media.tags,
          status: media.status,
          accessControl: media.accessControl,
          expiresAt: media.expiresAt,
          watermarkUrl: media.watermarkUrl,
          processingStatus: media.processingStatus,
          uploadedBy: media.uploadedBy,
          comments: media.comments,
          rating: media.rating,
          operationLogs: media.operationLogs,
        })),
        count: mediaList.length,
      },
      `Media with status '${status}' retrieved successfully.`
    ).send(res);
  }),

  filterMediaByAccessControl: asyncHandler(async (req, res) => {
    const { accessControl } = req.query;

    if (
      !accessControl ||
      !["public", "private", "restricted"].includes(accessControl)
    ) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Invalid or missing 'accessControl'. Allowed values: public, private, restricted."
      );
    }

    const mediaList = await Media.find({
      accessControl,
      isDeleted: false,
    }).sort({ createdAt: -1 });

    return new ApiResponse(
      StatusCodes.OK,
      {
        media: mediaList.map((media) => ({
          id: media._id,
          type: media.type,
          url: media.url,
          thumbnailUrl: media.thumbnailUrl,
          caption: media.caption,
          duration: media.duration,
          format: media.format,
          size: media.size,
          metadata: media.metadata,
          tags: media.tags,
          status: media.status,
          accessControl: media.accessControl,
          expiresAt: media.expiresAt,
          watermarkUrl: media.watermarkUrl,
          processingStatus: media.processingStatus,
          uploadedBy: media.uploadedBy,
          comments: media.comments,
          rating: media.rating,
          operationLogs: media.operationLogs,
        })),
        count: mediaList.length,
      },
      `Media with access control '${accessControl}' retrieved successfully.`
    ).send(res);
  }),

  filterMediaByExpiry: asyncHandler(async (req, res) => {
    const { status } = req.query;

    const now = new Date();
    let filter = { isDeleted: false };

    if (status === "expired") {
      filter.expiresAt = { $ne: null, $lt: now };
    } else {
      filter.$or = [{ expiresAt: null }, { expiresAt: { $gt: now } }];
    }

    const mediaList = await Media.find(filter).sort({ createdAt: -1 });

    return new ApiResponse(
      StatusCodes.OK,
      {
        media: mediaList,
        count: mediaList.length,
      },
      `Media filtered by ${
        status === "expired" ? "expired" : "active"
      } status successfully.`
    ).send(res);
  }),

  softDeleteMedia: asyncHandler(async (req, res) => {
    const { mediaId } = req.params;
    const userId = req.user._id;

    if (!mongoose.Types.ObjectId.isValid(mediaId)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid media ID.");
    }

    const media = await Media.findOne({ _id: mediaId, isDeleted: false });

    if (!media) {
      throw new ApiError(
        StatusCodes.NOT_FOUND,
        "Media not found or already deleted."
      );
    }

    media.isDeleted = true;

    media.operationLogs.push({
      action: "delete",
      user: userId,
    });

    await media.save({ validateBeforeSave: false });

    return new ApiResponse(StatusCodes.OK, "Media deleted successfully.").send(
      res
    );
  }),

  getExpiredMedia: asyncHandler(async (req, res) => {
    const now = new Date();

    const expiredMedia = await Media.find({
      expiresAt: { $ne: null, $lte: now },
      isDeleted: false,
    }).populate("uploadedBy", "fullName email");

    return new ApiResponse(
      StatusCodes.OK,
      expiredMedia,
      "Expired media fetched successfully."
    ).send(res);
  }),

  getAllMediaForAdmin: asyncHandler(async (req, res) => {
    const {
      page = 1,
      limit = 20,
      type,
      status,
      accessControl,
      search,
      includeDeleted = false,
    } = req.query;

    const filter = {};

    if (type) filter.type = type;
    if (status) filter.status = status;
    if (accessControl) filter.accessControl = accessControl;
    if (!JSON.parse(includeDeleted)) filter.isDeleted = false;
    if (search) {
      filter.$or = [
        { caption: { $regex: search, $options: "i" } },
        { tags: { $regex: search, $options: "i" } },
        { format: { $regex: search, $options: "i" } },
      ];
    }

    const media = await Media.find(filter)
      .populate("uploadedBy", "name email")
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(parseInt(limit));

    const total = await Media.countDocuments(filter);

    return new ApiResponse(
      StatusCodes.OK,
      {
        data: media.map((item) => ({
          id: item._id,
          type: item.type,
          url: item.url,
          thumbnailUrl: item.thumbnailUrl,
          caption: item.caption,
          duration: item.duration,
          format: item.format,
          size: item.size,
          metadata: item.metadata,
          tags: item.tags,
          status: item.status,
          accessControl: item.accessControl,
          expiresAt: item.expiresAt,
          watermarkUrl: item.watermarkUrl,
          processingStatus: item.processingStatus,
          uploadedBy: item.uploadedBy,
        })),
        total,
        page: parseInt(page),
        limit: parseInt(limit),
        totalPages: Math.ceil(total / limit),
      },
      "Media fetched successfully for admin"
    ).send(res);
  }),

  bulkApproveMedia: asyncHandler(async (req, res) => {
    const { mediaIds } = req.body;

    if (!Array.isArray(mediaIds) || mediaIds.length === 0) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "No media IDs provided. Please provide a valid array of media IDs."
      );
    }

    try {
      const result = await Media.updateMany(
        { _id: { $in: mediaIds } },
        { $set: { status: "approved" } }
      );

      if (result.nModified === 0) {
        throw new ApiError(
          StatusCodes.NOT_FOUND,
          "No media found with the provided IDs to approve."
        );
      }

      return new ApiResponse(
        StatusCodes.OK,
        { updatedCount: result.nModified },
        `${result.nModified} media items have been successfully approved.`
      ).send(res);
    } catch (error) {
      console.error(error);
      throw new ApiError(
        StatusCodes.INTERNAL_SERVER_ERROR,
        "An error occurred while approving the media. Please try again later."
      );
    }
  }),

  bulkRejectMedia: asyncHandler(async (req, res) => {
    const { mediaIds } = req.body;

    if (!Array.isArray(mediaIds) || mediaIds.length === 0) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "No media IDs provided. Please provide a valid array of media IDs."
      );
    }

    try {
      const result = await Media.updateMany(
        { _id: { $in: mediaIds } },
        { $set: { status: "rejected" } }
      );

      if (result.nModified === 0) {
        throw new ApiError(
          StatusCodes.NOT_FOUND,
          "No media found with the provided IDs to reject."
        );
      }

      return new ApiResponse(
        StatusCodes.OK,
        { updatedCount: result.nModified },
        `${result.nModified} media items have been successfully rejected.`
      ).send(res);
    } catch (error) {
      console.error(error);
      throw new ApiError(
        StatusCodes.INTERNAL_SERVER_ERROR,
        "An error occurred while rejecting the media. Please try again later."
      );
    }
  }),
};

export default MediaController;
