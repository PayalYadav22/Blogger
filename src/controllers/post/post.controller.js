import mongoose from "mongoose";
import { StatusCodes } from "http-status-codes";
import Post from "../../models/post.model.js";
import ApiError from "../../utils/apiError.js";
import ApiResponse from "../../utils/apiResponse.js";
import asyncHandler from "../../middleware/asyncHandler.middleware.js";
import { VIEW_LIMIT_DURATION } from "../../constants/constant.config.js";
import {
  uploadFileToCloudinary,
  deleteFileFromCloudinary,
} from "../../config/cloudinary.config.js";
import User from "../../models/user.model.js";

const incrementViewCountIfNeeded = async (postId, viewedBy = [], viewerIP) => {
  const alreadyViewed = viewedBy.some((v) => v.ip === viewerIP);
  if (alreadyViewed) return;

  await Post.findByIdAndUpdate(postId, {
    $inc: { views: 1 },
    $push: { viewedBy: { ip: viewerIP } },
  });
};

const PostController = {
  createPost: asyncHandler(async (req, res) => {
    const {
      title,
      content,
      excerpt,
      coverImageAltText,
      author,
      tags,
      categories,
    } = req.body;
    // Validate required fields

    if (
      [title, content, excerpt, author, coverImageAltText].some(
        (field) => !field
      )
    ) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Title, Content, Excerpt, CoverImageAltText, and Author are required."
      );
    }

    // Validate tags array
    if (!Array.isArray(tags) || tags.length === 0 || tags.length > 5) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Tags must be a non-empty array with a maximum of 5 items."
      );
    }

    // Validate categories array
    if (
      !Array.isArray(categories) ||
      categories.length === 0 ||
      categories.length > 5
    ) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Categories must be a non-empty array with a maximum of 5 items."
      );
    }

    // Validate and process banner image
    const bannerImageLocalFilePath = req?.file?.path;
    if (!bannerImageLocalFilePath) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Banner image is required. Please upload a valid image."
      );
    }
    let bannerImage;
    try {
      bannerImage = await uploadFileToCloudinary(bannerImageLocalFilePath);
      if (!bannerImage) {
        throw new ApiError(StatusCodes.BAD_REQUEST, "Failed to upload image.");
      }
    } catch (error) {
      // If the image upload fails, delete the file from Cloudinary (if it exists)
      if (bannerImage && bannerImage.publicId) {
        await deleteFileFromCloudinary(bannerImage.publicId);
      }
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Failed to upload image. Please try again or check the Cloudinary upload process."
      );
    }

    // Generate slug from the title
    const slug = title.toLowerCase().split(" ").join("-");
    // Create the post
    let post;
    try {
      post = await Post.create({
        ...req.body,
        title,
        content,
        excerpt,
        coverImageAltText,
        author,
        tags: tags.map((t) => t.toLowerCase()),
        categories: categories.map((c) => c.toLowerCase()),
        slug,
        bannerImage: {
          url: bannerImage.secure_url,
          publicId: bannerImage.public_id,
        },
      });
    } catch (error) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Failed to create post. Please try again."
      );
    }

    if (!post) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid Post.");
    }

    // Respond with the created post
    return new ApiResponse(
      StatusCodes.CREATED,
      post,
      "Post Created Successfully."
    ).send(res);
  }),

  getAllPosts: asyncHandler(async (req, res) => {
    const {
      query,
      limit = 10,
      page = 1,
      isPublished,
      tags,
      categories,
      isFeatured,
    } = req.query;

    const skip = (page - 1) * limit;

    const filter = {
      $and: [{ isDeleted: false }],
    };

    if (query) {
      const searchRegex = new RegExp(query, "i");
      filter.$and.push({
        $or: [
          { title: searchRegex },
          { slug: searchRegex },
          { content: searchRegex },
          { excerpt: searchRegex },
          { author: searchRegex },
          { tags: { $in: [searchRegex] } },
          { categories: { $in: [searchRegex] } },
        ],
      });
    }

    // Filter by published status if provided
    if (isPublished !== undefined) {
      filter.$and.push({ isPublished: isPublished === "true" });
    }

    // Filter by featured status if provided
    if (isFeatured !== undefined) {
      filter.$and.push({ isFeatured: isFeatured === "true" });
    }

    // Filter by tags if provided
    if (tags) {
      filter.$and.push({ tags: { $in: tags.split(",") } });
    }

    // Filter by categories if provided
    if (categories) {
      filter.$and.push({ categories: { $in: categories.split(",") } });
    }

    // Query the posts based on the filter and pagination
    const posts = await Post.find(filter)
      .select(
        "title slug content excerpt bannerImage author tags categories isPublished isFeatured createdAt"
      )
      .limit(Number(limit))
      .skip(Number(skip))
      .sort({ createdAt: -1 })
      .lean();

    // Get total posts count for pagination purposes
    const totalResults = await Post.countDocuments(filter);

    // Respond with posts and pagination info
    return new ApiResponse(
      StatusCodes.OK,
      {
        posts: posts.map((post) => ({
          postId: post.id,
          title: post.title,
          slug: post.slug,
          excerpt: post.excerpt,
          author: post.author,
          bannerImage: post.bannerImage,
          coverImageAltText: post.coverImageAltText,
          tags: post.tags,
          categories: post.categories,
        })),
        count: posts.length,
        totalResults,
        currentPage: Number(page),
        totalPages: Math.ceil(totalResults / limit),
      },
      "Posts fetched successfully"
    ).send(res);
  }),

  getPostById: asyncHandler(async (req, res) => {
    const { id } = req.params;

    // Validate ObjectId
    if (!mongoose.Types.ObjectId.isValid(id)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, null, "Invalid Id.");
    }

    // Fetch the post by ID
    const post = await Post.findById(id)
      .populate("author", "name email")
      .populate("media", "url")
      .lean();

    // Check if post exists
    if (!post) {
      return new ApiResponse(
        StatusCodes.NOT_FOUND,
        null,
        "Post not found"
      ).send(res);
    }

    return new ApiResponse(
      StatusCodes.OK,
      {
        postId: post.id,
        title: post.title,
        slug: post.slug,
        excerpt: post.excerpt,
        author: post.author,
        bannerImage: post.bannerImage,
        coverImageAltText: post.coverImageAltText,
        tags: post.tags,
        categories: post.categories,
      },
      "Post fetched successfully"
    ).send(res);
  }),

  updatePostById: asyncHandler(async (req, res) => {
    const { id } = req.params;

    const {
      title,
      content,
      excerpt,
      coverImageAltText,
      author,
      tags,
      categories,
    } = req.body;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid Id.");
    }

    // Find the post
    const post = await Post.findById(id);
    if (!post) {
      throw new ApiError(StatusCodes.NOT_FOUND, "Post not found.");
    }

    // Update only the fields provided in the request body
    if (title) {
      post.title = title;
      post.slug = title.toLowerCase().split(" ").join("-"); // Regenerate slug from title
    }

    if (content) {
      post.content = content;
    }

    if (excerpt) {
      post.excerpt = excerpt;
    }

    if (coverImageAltText) {
      post.coverImageAltText = coverImageAltText;
    }

    if (author) {
      post.author = author;
    }

    // Validate and update tags if provided
    if (tags) {
      if (!Array.isArray(tags) || tags.length === 0 || tags.length > 5) {
        throw new ApiError(
          StatusCodes.BAD_REQUEST,
          "Tags must be a non-empty array with a maximum of 5 items."
        );
      }
      post.tags = tags.map((t) => t.toLowerCase());
    }

    // Validate and update categories if provided
    if (categories) {
      if (
        !Array.isArray(categories) ||
        categories.length === 0 ||
        categories.length > 5
      ) {
        throw new ApiError(
          StatusCodes.BAD_REQUEST,
          "Categories must be a non-empty array with a maximum of 5 items."
        );
      }
      post.categories = categories.map((c) => c.toLowerCase());
    }

    // Process banner image if provided
    const bannerImageLocalFilePath = req?.file?.path;
    if (bannerImageLocalFilePath) {
      try {
        const bannerImage = await uploadFileToCloudinary(
          bannerImageLocalFilePath
        );
        if (!bannerImage) {
          throw new ApiError(
            StatusCodes.BAD_REQUEST,
            "Failed to upload image."
          );
        }
        post.bannerImage = {
          url: bannerImage.secure_url,
          publicId: bannerImage.public_id,
        };
      } catch (error) {
        throw new ApiError(
          StatusCodes.BAD_REQUEST,
          "Failed to upload image. Please try again or check the Cloudinary upload process."
        );
      }
    }

    // Save the updated post
    try {
      await post.save({ validateBeforeSave: false });
    } catch (error) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Failed to update post. Please try again."
      );
    }

    // Respond with the updated post
    return new ApiResponse(
      StatusCodes.OK,
      {
        postId: post.id,
        title: post.title,
        slug: post.slug,
        excerpt: post.excerpt,
        author: post.author,
        bannerImage: post.bannerImage,
        coverImageAltText: post.coverImageAltText,
        tags: post.tags,
        categories: post.categories,
      },
      "Post updated successfully."
    ).send(res);
  }),

  deletePostById: asyncHandler(async (req, res) => {
    const { id } = req.params;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid Id.");
    }

    const post = await Post.findById(id);

    if (!post) {
      throw new ApiError(StatusCodes.NOT_FOUND, "Post not found.");
    }

    if (post.bannerImage?.publicId) {
      try {
        await deleteFileFromCloudinary(post.bannerImage.publicId);
      } catch (error) {
        throw new ApiError(
          StatusCodes.INTERNAL_SERVER_ERROR,
          "Failed to delete image from Cloudinary."
        );
      }
    }

    post.isDeleted = true;

    await post.save({ validateBeforeSave: true });

    return new ApiResponse(
      StatusCodes.OK,
      "Post deleted successfully, image removed from Cloudinary."
    ).send(res);
  }),

  getPostBySlug: asyncHandler(async (req, res) => {
    const { slug } = req.params;
    const viewerIP = req.ip;

    if (!slug?.trim()) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Slug is required.");
    }

    const post = await Post.findOne({ slug, isDeleted: false })
      .populate("author", "name email avatar")
      .populate("collaborators.user", "name email")
      .populate("media")
      .lean();

    if (!post) {
      throw new ApiError(StatusCodes.NOT_FOUND, "Post not found.");
    }

    // Helper: increment view count if new viewer
    await incrementViewCountIfNeeded(post._id, post.viewedBy, viewerIP);

    return new ApiResponse(
      StatusCodes.OK,
      {
        postId: post._id,
        title: post.title,
        slug: post.slug,
        excerpt: post.excerpt,
        author: post.author,
        bannerImage: post.bannerImage,
        coverImageAltText: post.coverImageAltText,
        tags: post.tags,
        categories: post.categories,
        views:
          post.views + (!post.viewedBy?.some((v) => v.ip === viewerIP) ? 1 : 0),
      },
      "Post retrieved successfully."
    ).send(res);
  }),

  publishPost: asyncHandler(async (req, res) => {
    const { slug } = req.params;
    const userId = req.user?._id;

    if (!mongoose.Types.ObjectId.isValid(userId)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid Id.");
    }

    if (!slug?.trim()) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Slug is required.");
    }

    const post = await Post.findOne({ slug, isDeleted: false });

    if (!post) {
      throw new ApiError(StatusCodes.NOT_FOUND, "Post not found.");
    }

    if (post.isPublished) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Post is already published.");
    }

    const isAuthor = post.author.equals(userId);

    const isCollaboratorWithWrite = post.collaborators?.some(
      (c) => c.user.equals(userId) && c.permissions.includes("write")
    );

    const isAdmin = req.user?.role === "admin";

    if (!isAuthor && !isCollaboratorWithWrite && !isAdmin) {
      throw new ApiError(
        StatusCodes.FORBIDDEN,
        "You are not allowed to publish this post."
      );
    }

    post.isPublished = true;
    post.publishedAt = new Date();
    post.needsApproval = false;

    await post.save({
      validateBeforeSave: false,
    });

    return new ApiResponse(
      StatusCodes.OK,
      {
        postId: post._id,
        slug: post.slug,
        title: post.title,
        publishedAt: post.publishedAt,
      },
      "Post published successfully."
    ).send(res);
  }),

  unpublishPost: asyncHandler(async (req, res) => {
    const { slug } = req.params;
    const userId = req.user?._id;

    if (!mongoose.Types.ObjectId.isValid(userId)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid Id.");
    }

    if (!slug?.trim()) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Slug is required.");
    }

    const post = await Post.findOne({ slug, isDeleted: false });

    if (!post) {
      throw new ApiError(StatusCodes.NOT_FOUND, "Post not found.");
    }

    if (!post.isPublished) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Post is already unpublished."
      );
    }

    const isAuthor = post.author.equals(userId);
    const isCollaboratorWithWrite = post.collaborators?.some(
      (c) => c.user.equals(userId) && c.permissions.includes("write")
    );

    const isAdmin = req.user?.role === "admin";

    if (!isAuthor && !isCollaboratorWithWrite && !isAdmin) {
      throw new ApiError(
        StatusCodes.FORBIDDEN,
        "You are not allowed to unpublish this post."
      );
    }

    // Unpublish the post
    post.isPublished = false;
    post.publishedAt = null;
    post.needsApproval = true;

    await post.save({ validateBeforeSave: false });

    return new ApiResponse(
      StatusCodes.OK,
      {
        postId: post._id,
        slug: post.slug,
        title: post.title,
      },
      "Post unpublished successfully."
    ).send(res);
  }),

  approvePost: asyncHandler(async (req, res) => {
    const { slug } = req.params;
    const approverId = req.user?._id;

    if (!mongoose.Types.ObjectId.isValid(approverId)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid Id.");
    }

    if (!slug?.trim()) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Slug is required.");
    }

    const post = await Post.findOne({ slug, isDeleted: false });

    if (!post) {
      throw new ApiError(StatusCodes.NOT_FOUND, "Post not found.");
    }

    if (!post.needsApproval) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Post is already approved.");
    }

    const isAllowed = ["admin", "moderator"].includes(req.user.role);

    if (!isAllowed) {
      throw new ApiError(
        StatusCodes.FORBIDDEN,
        "You are not authorized to approve posts."
      );
    }

    post.needsApproval = false;
    post.approvedAt = new Date();
    post.approvedBy = approverId;

    await post.save({ validateBeforeSave: false });

    return new ApiResponse(
      StatusCodes.OK,
      { slug: post.slug, title: post.title },
      "Post approved successfully."
    ).send(res);
  }),

  featurePost: asyncHandler(async (req, res) => {
    const { id } = req.params;

    const { isFeatured } = req.body;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid Id. ");
    }

    const post = await Post.findOne({ _id: id, isDeleted: false });

    if (!post) {
      throw new ApiError(StatusCodes.NOT_FOUND, "Post not found.");
    }

    post.isFeatured = !isFeatured;

    await post.save({ validateBeforeSave: false });

    return new ApiResponse(
      StatusCodes.OK,
      {
        postId: post._id,
        title: post.title,
        slug: post.slug,
        excerpt: post.excerpt,
        author: post.author,
        bannerImage: post.bannerImage,
        coverImageAltText: post.coverImageAltText,
        tags: post.tags,
        categories: post.categories,
      },
      `Post ${isFeatured ? "featured" : "unfeatured"} successfully.`
    ).send(res);
  }),

  requestApproval: asyncHandler(async (req, res) => {
    const { id } = req.params;
    const userId = req.user._id;

    [id, userId].map((i) => {
      if (!mongoose.Types.ObjectId.isValid(i)) {
        throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid Id.");
      }
    });

    const post = await Post.findOne({ _id: id, isDeleted: false });

    if (!post) {
      throw new ApiError(StatusCodes.NOT_FOUND, "Post not found.");
    }

    const isAuthor = post.author.toString() === userId.toString();

    const isCollaborator = post.collaborators?.some(
      (collab) =>
        collab.user.toString() === userId.toString() &&
        collab.permissions.includes("write")
    );

    if (!isAuthor && !isCollaborator) {
      throw new ApiError(
        StatusCodes.FORBIDDEN,
        "You are not allowed to request approval for this post."
      );
    }

    post.needsApproval = true;
    post.approvedAt = null;
    post.approvedBy = null;

    await post.save({ validateBeforeSave: false });

    return new ApiResponse(
      StatusCodes.OK,
      {
        postId: post._id,
        title: post.title,
        slug: post.slug,
        needsApproval: post.needsApproval,
      },
      "Approval request submitted successfully."
    ).send(res);
  }),

  addCollaborator: asyncHandler(async (req, res) => {
    const { id } = req.params;

    const { userId, role, permissions } = req.body;

    [id, userId].map((i) => {
      if (!mongoose.Types.ObjectId.isValid(i)) {
        throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid Id.");
      }
    });

    const user = await User.findById(userId);

    if (!user) {
      throw new ApiError(StatusCodes.NOT_FOUND, "User not found.");
    }

    const validPermissions = ["read", "write", "delete"];

    if (
      permissions.some((permission) => !validPermissions.includes(permission))
    ) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Invalid permissions provided."
      );
    }

    // Find the post
    const post = await Post.findOne({ _id: id, isDeleted: false });

    if (!post) {
      throw new ApiError(StatusCodes.NOT_FOUND, "Post not found.");
    }

    const isAuthor = post.author.toString() === req.user._id.toString();

    const isEditor = post.collaborators.some(
      (collab) =>
        collab.user.toString() === req.user._id.toString() &&
        collab.role === "editor"
    );

    if (!isAuthor && !isEditor) {
      throw new ApiError(
        StatusCodes.FORBIDDEN,
        "You do not have permission to add collaborators to this post."
      );
    }

    const existingCollaborator = post.collaborators.find(
      (collab) => collab.user.toString() === userId.toString()
    );

    if (existingCollaborator) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "User is already a collaborator."
      );
    }

    post.collaborators.push({
      user: userId,
      role: role || "viewer",
      permissions: permissions || ["read"],
    });

    await post.save({ validateBeforeSave: false });

    return new ApiResponse(
      StatusCodes.OK,
      {
        postId: post._id,
        title: post.title,
        slug: post.slug,
        collaborators: post.collaborators,
      },
      "Collaborator added successfully."
    ).send(res);
  }),

  removeCollaborator: asyncHandler(async (req, res) => {
    const { id } = req.params;

    const { userId } = req.body;

    [id, userId].map((i) => {
      if (!mongoose.Types.ObjectId.isValid(i)) {
        throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid Id.");
      }
    });

    const user = await User.findById(userId);

    if (!user) {
      throw new ApiError(StatusCodes.NOT_FOUND, "User not found.");
    }

    const post = await Post.findOne({ _id: id, isDeleted: false });

    if (!post) {
      throw new ApiError(StatusCodes.NOT_FOUND, "Post not found.");
    }

    // Permission check
    const isAuthor = post.author.toString() === req.user._id.toString();
    const isEditor = post.collaborators.some(
      (collab) =>
        collab.user.toString() === req.user._id.toString() &&
        collab.role === "editor"
    );

    if (!isAuthor && !isEditor) {
      throw new ApiError(
        StatusCodes.FORBIDDEN,
        "You do not have permission to remove collaborators."
      );
    }

    // Check if user is a collaborator
    const collaboratorIndex = post.collaborators.findIndex(
      (collab) => collab.user.toString() === userId.toString()
    );

    if (collaboratorIndex === -1) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "User is not a collaborator on this post."
      );
    }

    // Remove collaborator
    post.collaborators.splice(collaboratorIndex, 1);

    await post.save({ validateBeforeSave: false });

    return new ApiResponse(
      StatusCodes.OK,
      {
        postId: post._id,
        title: post.title,
        slug: post.slug,
        collaborators: post.collaborators,
      },
      "Collaborator removed successfully."
    ).send(res);
  }),

  updateCollaboratorPermissions: asyncHandler(async (req, res) => {
    const { id } = req.params;

    const { userId, permissions } = req.body;

    [id, userId].forEach((val) => {
      if (!mongoose.Types.ObjectId.isValid(val)) {
        throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid Id.");
      }
    });

    const user = await User.findById(userId);

    if (!user) {
      throw new ApiError(StatusCodes.NOT_FOUND, "User not found.");
    }

    const validPermissions = ["read", "write", "delete"];

    if (
      !Array.isArray(permissions) ||
      permissions.length === 0 ||
      permissions.length > 3 ||
      !permissions.every((p) => validPermissions.includes(p))
    ) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Permissions must include 1-3 values from: read, write, delete."
      );
    }

    const post = await Post.findOne({ _id: id, isDeleted: false });

    if (!post) {
      throw new ApiError(StatusCodes.NOT_FOUND, "Post not found.");
    }

    const isAuthor = post.author.toString() === req.user._id.toString();

    const isEditor = post.collaborators.some(
      (collab) =>
        collab.user.toString() === req.user._id.toString() &&
        collab.role === "editor"
    );

    if (!isAuthor && !isEditor) {
      throw new ApiError(
        StatusCodes.FORBIDDEN,
        "You don't have permission to update collaborator permissions."
      );
    }

    const collaborator = post.collaborators.find(
      (collab) => collab.user.toString() === userId
    );

    if (!collaborator) {
      throw new ApiError(
        StatusCodes.NOT_FOUND,
        "Collaborator not found on this post."
      );
    }

    collaborator.permissions = permissions;

    await post.save({ validateBeforeSave: false });

    return new ApiResponse(
      StatusCodes.OK,
      {
        postId: post._id,
        collaborator: {
          user: collaborator.user,
          role: collaborator.role,
          permissions: collaborator.permissions,
        },
      },
      "Collaborator permissions updated successfully."
    ).send(res);
  }),

  getPostsByTags: asyncHandler(async (req, res) => {
    const { tags = "", limit = 10, page = 1 } = req.query;

    const skip = (Number(page) - 1) * Number(limit);

    const tagArray = tags
      .split(",")
      .map((tag) => tag.trim().toLowerCase())
      .filter(Boolean);

    if (tagArray.length === 0) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "At least one valid tag is required."
      );
    }

    const filter = {
      $and: [{ isDeleted: false }, { tags: { $in: tagArray } }],
    };

    const posts = await Post.find(filter)
      .select(
        "title slug content excerpt bannerImage author tags categories isPublished isFeatured createdAt"
      )
      .limit(Number(limit))
      .skip(Number(skip))
      .sort({ createdAt: -1 })
      .lean();

    const totalResults = await Post.countDocuments(filter);

    return new ApiResponse(
      StatusCodes.OK,
      {
        posts: posts.map((post) => ({
          postId: post._id,
          title: post.title,
          slug: post.slug,
          excerpt: post.excerpt,
          author: post.author,
          bannerImage: post.bannerImage,
          coverImageAltText: post.coverImageAltText,
          tags: post.tags,
          categories: post.categories,
        })),
        count: posts.length,
        totalResults,
        currentPage: Number(page),
        totalPages: Math.ceil(totalResults / limit),
      },
      `Posts fetched successfully for tags: ${tagArray.join(", ")}`
    ).send(res);
  }),

  getPostsByCategories: asyncHandler(async (req, res) => {
    const { categories = "", limit = 10, page = 1 } = req.query;

    const skip = (Number(page) - 1) * Number(limit);

    const categoryArray = categories
      .split(",")
      .map((category) => category.trim().toLowerCase())
      .filter(Boolean);

    if (categoryArray.length === 0) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "At least one valid category is required."
      );
    }

    const filter = {
      $and: [{ isDeleted: false }, { categories: { $in: categoryArray } }],
    };

    const posts = await Post.find(filter)
      .select(
        "title slug content excerpt bannerImage author tags categories isPublished isFeatured createdAt"
      )
      .limit(Number(limit))
      .skip(Number(skip))
      .sort({ createdAt: -1 })
      .lean();

    const totalResults = await Post.countDocuments(filter);

    return new ApiResponse(
      StatusCodes.OK,
      {
        posts: posts.map((post) => ({
          postId: post._id,
          title: post.title,
          slug: post.slug,
          excerpt: post.excerpt,
          author: post.author,
          bannerImage: post.bannerImage,
          coverImageAltText: post.coverImageAltText,
          tags: post.tags,
          categories: post.categories,
        })),
        count: posts.length,
        totalResults,
        currentPage: Number(page),
        totalPages: Math.ceil(totalResults / limit),
      },
      `Posts fetched successfully for categories: ${categoryArray.join(", ")}`
    ).send(res);
  }),

  getFeaturedPosts: asyncHandler(async (req, res) => {
    const { limit = 10, page = 1 } = req.query;

    const skip = (Number(page) - 1) * Number(limit);

    const filter = {
      isFeatured: true,
      isPublished: true,
      isDeleted: false,
    };

    const posts = await Post.find(filter)
      .select(
        "title slug excerpt bannerImage coverImageAltText author tags categories isPublished isFeatured createdAt"
      )
      .limit(Number(limit))
      .skip(Number(skip))
      .sort({ createdAt: -1 })
      .populate("author", "name email")
      .lean();

    const totalResults = await Post.countDocuments(filter);

    return new ApiResponse(
      StatusCodes.OK,
      {
        posts: posts.map((post) => ({
          postId: post._id,
          title: post.title,
          slug: post.slug,
          excerpt: post.excerpt,
          author: post.author,
          bannerImage: post.bannerImage,
          coverImageAltText: post.coverImageAltText,
          tags: post.tags,
          categories: post.categories,
          isFeatured: post.isFeatured,
          isPublished: post.isPublished,
          createdAt: post.createdAt,
        })),
        count: posts.length,
        totalResults,
        currentPage: Number(page),
        totalPages: Math.ceil(totalResults / limit),
      },
      "Featured posts fetched successfully."
    ).send(res);
  }),

  getPostsByAuthor: asyncHandler(async (req, res) => {
    const { authorId } = req.params;

    const { limit = 10, page = 1 } = req.query;

    if (!mongoose.Types.ObjectId.isValid(authorId)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid author ID.");
    }

    // Pagination logic
    const skip = (Number(page) - 1) * Number(limit);

    const filter = {
      author: authorId,
      isDeleted: false,
    };

    // Find posts with pagination, sorting by createdAt, and populate the author's info
    const posts = await Post.find(filter)
      .select(
        "title slug excerpt bannerImage coverImageAltText tags categories isPublished isFeatured createdAt"
      )
      .limit(Number(limit))
      .skip(Number(skip))
      .sort({ createdAt: -1 })
      .populate("author", "name email")
      .lean();

    // Calculate the total number of posts by this author
    const totalResults = await Post.countDocuments(filter);

    return new ApiResponse(
      StatusCodes.OK,
      {
        posts: posts.map((post) => ({
          postId: post._id,
          title: post.title,
          slug: post.slug,
          excerpt: post.excerpt,
          author: post.author,
          bannerImage: post.bannerImage,
          coverImageAltText: post.coverImageAltText,
          tags: post.tags,
          categories: post.categories,
          isFeatured: post.isFeatured,
          isPublished: post.isPublished,
          createdAt: post.createdAt,
        })),
        count: posts.length,
        totalResults,
        currentPage: Number(page),
        totalPages: Math.ceil(totalResults / limit),
      },
      `Posts by author ${authorId} fetched successfully.`
    ).send(res);
  }),

  getPostsNeedingApproval: asyncHandler(async (req, res) => {
    const { limit = 10, page = 1 } = req.query;

    const skip = (Number(page) - 1) * Number(limit);

    const filter = {
      needsApproval: true,
      isDeleted: false,
    };

    const posts = await Post.find(filter)
      .select(
        "title slug excerpt bannerImage coverImageAltText tags categories createdAt needsApproval"
      )
      .limit(Number(limit))
      .skip(Number(skip))
      .sort({ createdAt: -1 })
      .populate("author", "name email")
      .lean();

    const totalResults = await Post.countDocuments(filter);

    return new ApiResponse(
      StatusCodes.OK,
      {
        posts: posts.map((post) => ({
          postId: post._id,
          title: post.title,
          slug: post.slug,
          excerpt: post.excerpt,
          bannerImage: post.bannerImage,
          coverImageAltText: post.coverImageAltText,
          tags: post.tags,
          categories: post.categories,
          needsApproval: post.needsApproval,
          createdAt: post.createdAt,
          author: post.author,
        })),
        count: posts.length,
        totalResults,
        currentPage: Number(page),
        totalPages: Math.ceil(totalResults / limit),
      },
      `Posts needing approval fetched successfully.`
    ).send(res);
  }),

  getPostsByDateRange: asyncHandler(async (req, res) => {
    const { startDate, endDate, field = "createdAt" } = req.query;

    // Validate required dates
    if (!startDate || !endDate) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Both 'startDate' and 'endDate' are required."
      );
    }

    // Parse and validate date inputs
    const start = new Date(startDate);
    const end = new Date(endDate);

    if (isNaN(start) || isNaN(end)) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Invalid date format. Use ISO format (YYYY-MM-DD)."
      );
    }

    // Ensure start date is not after end date
    if (start > end) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "'startDate' cannot be later than 'endDate'."
      );
    }

    // Validate allowed fields
    const validFields = ["createdAt", "updatedAt", "publishedAt"];
    if (!validFields.includes(field)) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        `Invalid date field. Allowed fields: ${validFields.join(", ")}.`
      );
    }

    // Build filter
    const filter = {
      [field]: { $gte: start, $lte: end },
      isDeleted: false,
    };

    // Query posts
    const posts = await Post.find(filter)
      .select(
        "title slug excerpt author tags categories isPublished isFeatured createdAt publishedAt"
      )
      .sort({ [field]: -1 })
      .populate("author", "name email")
      .lean();

    // Response message based on result
    const message =
      posts.length > 0
        ? `Posts fetched successfully from ${startDate} to ${endDate} based on '${field}'.`
        : `No posts found from ${startDate} to ${endDate} based on '${field}'.`;

    // Send response
    return new ApiResponse(
      StatusCodes.OK,
      {
        count: posts.length,
        posts,
      },
      message
    ).send(res);
  }),

  incrementViewCount: asyncHandler(async (req, res) => {
    const { slug } = req.params;
    const ip = req.ip;

    const post = await Post.findOne({ slug });
    if (!post) {
      throw new ApiError(StatusCodes.NOT_FOUND, "Post not found");
    }

    const now = Date.now();
    const viewLimitDuration = VIEW_LIMIT_DURATION;

    // Check if the post has been recently viewed by the same IP
    const alreadyViewed = post.viewedBy.some((entry) => {
      const lastViewedAt = new Date(entry.viewedAt).getTime();
      return entry.ip === ip && now - lastViewedAt < viewLimitDuration;
    });

    // If the post hasn't been viewed recently, increment the view count
    if (!alreadyViewed) {
      post.views += 1;
      post.viewedBy.push({ ip, viewedAt: now });

      // Keep only views from the last 24 hours
      post.viewedBy = post.viewedBy.filter(
        (entry) =>
          now - new Date(entry.viewedAt).getTime() < 24 * 60 * 60 * 1000
      );

      await post.save({ validateBeforeSave: false });
    }

    // Send the response
    return new ApiResponse(
      StatusCodes.OK,
      { views: post.views },
      alreadyViewed
        ? "View not counted (already viewed recently)"
        : "View counted"
    ).send(res);
  }),

  getPopularPosts: asyncHandler(async (req, res) => {
    const { limit = 10 } = req.query;

    const posts = await Post.find({
      isPublished: true,
      isDeleted: false,
    })
      .sort({ views: -1, publishedAt: -1 })
      .limit(Number(limit))
      .populate("author", "name email")
      .select("title slug views publishedAt excerpt bannerImage")
      .lean();

    if (!posts) {
      throw new ApiError(StatusCodes.NOT_FOUND, "Post not found.");
    }

    return new ApiResponse(
      StatusCodes.OK,
      {
        count: posts.length,
        posts: posts.map((post) => ({
          postId: post._id,
          title: post.title,
          slug: post.slug,
          excerpt: post.excerpt,
          author: post.author,
          bannerImage: post.bannerImage,
          coverImageAltText: post.coverImageAltText,
          tags: post.tags,
          categories: post.categories,
        })),
      },
      "Popular posts fetched successfully."
    ).send(res);
  }),

  getPostReadTime: asyncHandler(async (req, res) => {
    const { id } = req.params;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid Id.");
    }

    const post = await Post.findOne({ _id: id, isDeleted: false }).lean();

    if (!post) {
      throw new ApiError(StatusCodes.NOT_FOUND, "Post not found.");
    }

    const wordCount = post.content?.split(/\s+/).length || 0;
    const estimatedReadTime = Math.ceil(wordCount / 200);

    return new ApiResponse(
      StatusCodes.OK,
      {
        postId: post._id,
        title: post.title,
        readTime: estimatedReadTime,
        wordCount,
      },
      "Read time calculated successfully."
    ).send(res);
  }),

  getPostHistory: asyncHandler(async (req, res) => {
    const { id } = req.params;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid Id.");
    }

    const post = await Post.findOne({ _id: id, isDeleted: false })
      .select("title contentHistory")
      .populate("contentHistory.updatedBy", "name email")
      .lean();

    if (!post) {
      throw new ApiError(StatusCodes.NOT_FOUND, "Post not found.");
    }

    return new ApiResponse(
      StatusCodes.OK,
      {
        postId: post._id,
        title: post.title,
        historyCount: post.contentHistory.length,
        contentHistory: post.contentHistory,
      },
      "Post history fetched successfully."
    ).send(res);
  }),

  revertPostVersion: asyncHandler(async (req, res) => {
    const { id, versionIndex } = req.params;
    const userId = req.user?._id;

    [id, userId].map((i) => {
      if (!mongoose.Types.ObjectId.isValid(i)) {
        throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid Id.");
      }
    });

    if (versionIndex === undefined) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "version index is required.");
    }

    const post = await Post.findOne({ _id: id, isDeleted: false });

    if (!post) {
      throw new ApiError(StatusCodes.NOT_FOUND, "Post not found.");
    }

    console.log(await Post.find());

    const history = post.contentHistory;

    if (
      !Array.isArray(history) ||
      versionIndex < 0 ||
      versionIndex >= history.length
    ) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid version index.");
    }

    const versionToRevert = history[versionIndex];

    if (!versionToRevert || !versionToRevert.content) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Selected version has no content."
      );
    }

    post.contentHistory.push({
      content: post.content,
      updatedAt: new Date(),
      updatedBy: userId,
    });

    post.content = versionToRevert.content;
    post.draftVersion += 1;
    await post.save({ validateBeforeSave: false });

    return new ApiResponse(
      StatusCodes.OK,
      {
        postId: post._id,
        revertedToVersion: versionIndex,
        currentDraftVersion: post.draftVersion,
        updatedContent: post.content,
      },
      "Post successfully reverted to selected version."
    ).send(res);
  }),

  getPostComments: asyncHandler(async (req, res) => {}),

  getLikesCount: asyncHandler(async (req, res) => {}),

  getPostMeta: asyncHandler(async (req, res) => {
    const { id } = req.params;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid Id.");
    }

    const post = await Post.findById(postId).select("meta");

    if (!post) {
      throw new ApiError(StatusCodes.NOT_FOUND, "Post not found.");
    }

    return new ApiResponse(
      StatusCodes.OK,
      { meta: post.meta },
      "Post metadata fetched successfully"
    ).send(res);
  }),

  updatePostMeta: asyncHandler(async (req, res) => {
    const { id } = req.params;
    const { meta } = req.body;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid Id.");
    }

    // Fetch the post
    const post = await Post.findById(id);

    if (!post) {
      throw new ApiError(StatusCodes.NOT_FOUND, "Post not found.");
    }

    post.meta.title = meta.title || post.meta.title;
    post.meta.description = meta.description || post.meta.description;

    await post.save({ validateBeforeSave: false });

    return new ApiResponse(
      StatusCodes.OK,
      { meta: post.meta },
      "Post metadata updated successfully"
    ).send(res);
  }),

  restorePost: asyncHandler(async (req, res) => {
    const { id } = req.params;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Invalid Id.");
    }

    const post = await Post.findById(id);

    // If the post is not found, throw an error
    if (!post) {
      throw new ApiError(StatusCodes.NOT_FOUND, "Post not found.");
    }

    if (!post.isDeleted) {
      return new ApiResponse(
        StatusCodes.Ok,
        "Post is not deleted and does not need to be restored."
      ).send(res);
    }

    post.isDeleted = false;

    await post.save({ validateBeforeSave: false });

    return new ApiResponse(200, { post }, "Post restored successfully.").send(
      res
    );
  }),
};

export default PostController;
