import express from "express";
import PostController from "../controllers/post/post.controller.js";
import authenticate from "../middleware/authenticate.middleware.js";
import authorizeRoles from "../middleware/authorizeRoles.middleware.js";
import upload from "../middleware/multer.middleware.js";
const router = express.Router();

// Middleware to authenticate user for all routes unless stated otherwise
router.use(authenticate);

router.route("/featured-posts").get(PostController.getFeaturedPosts);

// GET /posts/by-tags?tags=tag1,tag2
router.route("/by-tags").get(PostController.getPostsByTags);

// GET /posts/by-categories?categories=cat1,cat2
router.route("/by-categories").get(PostController.getPostsByCategories);

// GET /posts/by-author/:authorId
router.route("/by-author/:authorId").get(PostController.getPostsByAuthor);

// GET /posts/needs-approval
router
  .route("/needs-approval")
  .get(
    authorizeRoles("admin", "editor"),
    PostController.getPostsNeedingApproval
  );

// GET /posts/date-range?start=YYYY-MM-DD&end=YYYY-MM-DD
router.route("/date-range").get(PostController.getPostsByDateRange);

// PATCH /posts/:id/restore
router
  .route("/:id/restore")
  .patch(authorizeRoles("admin", "editor"), PostController.restorePost);

// Slug-Based Routes
// Route to get a post by its slug (unique identifier)
router.route("/slug/:slug").get(PostController.getPostBySlug);

// Filter & Search Routes
// Route to fetch featured posts (usually selected or highlighted content)
router.route("/featured").get(PostController.getFeaturedPosts);

// Route to fetch popular posts (most viewed or interacted with posts)
router.route("/popular").get(PostController.getPopularPosts);

// Analytics & Engagement Routes
// Route to increment the view count for a specific post (tracked by post ID)
router.route("/:id/view").post(PostController.incrementViewCount);

// Route to get the estimated read time for a specific post (tracked by post ID)
router.route("/:id/read-time").get(PostController.getPostReadTime);

// Comments & Likes Routes
// Route to fetch all comments associated with a specific post (tracked by post ID)
router.route("/:id/comments").get(PostController.getPostComments);

// Route to fetch the like count for a specific post (tracked by post ID)
router.route("/:id/likes-count").get(PostController.getLikesCount);

// Basic CRUD Routes
// Route to create a new post (only accessible by users with certain roles)
router
  .route("/")
  .post(
    authorizeRoles("admin", "editor", "writer", "contributor"), // Role-based access control
    upload.single("bannerImage"),
    PostController.createPost
  )
  // Route to fetch all posts (accessible by various roles with read permissions)
  .get(
    authorizeRoles("admin", "editor", "viewer", "moderator", "subscriber"),
    PostController.getAllPosts
  );

// CRUD actions on a specific post (based on post ID)
router
  .route("/:id")
  // Route to get a specific post by its ID
  .get(
    authorizeRoles("admin", "editor", "viewer", "moderator", "subscriber"),
    PostController.getPostById
  )
  // Route to update a post by its ID (restricted to admin, editor, and writer roles)
  .patch(
    authorizeRoles("admin", "editor", "writer"),
    PostController.updatePostById
  )
  // Route to delete a post by its ID (restricted to admin and editor roles)
  .delete(authorizeRoles("admin", "editor"), PostController.deletePostById);

// Route to feature a post (restricted to admin and editor roles)
router
  .route("/:id/feature")
  .patch(authorizeRoles("admin", "editor"), PostController.featurePost);

// Publishing & Moderation Routes
// Route to publish a post (restricted to admin and editor roles)
router
  .route("/:slug/publish")
  .patch(authorizeRoles("admin", "editor"), PostController.publishPost);

// Route to unpublish a post (restricted to admin and editor roles)
router
  .route("/:slug/unpublish")
  .patch(authorizeRoles("admin", "editor"), PostController.unpublishPost);

// Route to approve a post (restricted to admin and moderator roles)
router
  .route("/:slug/approve")
  .patch(authorizeRoles("admin", "moderator"), PostController.approvePost);

// Route to request approval for a post (only accessible by writers and contributors)
router
  .route("/:id/request-approval")
  .patch(
    authorizeRoles("admin", "writer", "contributor"),
    PostController.requestApproval
  );

// Collaboration Routes
// Route to add a collaborator to a post (restricted to admin, editor, and writer roles)
router
  .route("/:id/collaborators")
  .post(
    authorizeRoles("admin", "editor", "writer"),
    PostController.addCollaborator
  )
  .patch(
    authorizeRoles("admin", "editor", "writer"),
    PostController.updateCollaboratorPermissions
  )
  .delete(
    authorizeRoles("admin", "editor", "writer"),
    PostController.removeCollaborator
  );

// Posts Needing Approval Route
// Route to get posts that are pending approval (restricted to admin and moderator roles)
router
  .route("/needs-approval")
  .get(
    authorizeRoles("admin", "moderator"),
    PostController.getPostsNeedingApproval
  );

// Version History Routes
// Route to fetch the version history of a post (restricted to admin, editor, and writer roles)
router
  .route("/:id/history")
  .get(
    authorizeRoles("admin", "editor", "writer"),
    PostController.getPostHistory
  );

// Route to revert a post to a previous version (restricted to admin and editor roles)
router
  .route("/:id/revert/:versionIndex")
  .get(authorizeRoles("admin", "editor"), PostController.revertPostVersion);

// Meta & SEO Routes
// Route to get or update metadata for a post (restricted to admin and editor roles)
router
  .route("/:id/meta")
  .get(PostController.getPostMeta)
  .put(authorizeRoles("admin", "editor"), PostController.updatePostMeta);

// Restore / Soft Delete Routes
// Route to restore a soft-deleted post (restricted to admin and editor roles)
router
  .route("/:id/restore")
  .patch(authorizeRoles("admin", "editor"), PostController.restorePost);

export default router;
