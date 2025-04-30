import express from "express";
import CommentController from "../controllers/comment.controller.js";
import authenticate from "../middleware/authenticate.middleware.js";
import authorizeRoles from "../middleware/authorizeRoles.middleware.js";

const router = express.Router();

// ----------------------------- Public Routes ----------------------------

// Get comments by post ID
router.route("/post/:postId").get(CommentController.getCommentsByPost);

// Get comments by user ID
router.route("/user/:userId").get(CommentController.getCommentsByUser);

// Get replies by comment ID
router.route("/:id/replies").get(CommentController.getRepliesByComment);

// ----------------------------- Private Routes ----------------------------

router.use(authenticate);

// Create a new comment (requires authentication)
router.route("/").post(CommentController.createComment);

// Like a comment (requires authentication)
router.route("/:id/like").post(CommentController.likeComment);

// Dislike a comment (requires authentication)
router.route("/:id/dislike").post(CommentController.dislikeComment);

// Report a comment (requires authentication)
router.route("/:id/report").post(CommentController.reportComment);

// Get a specific comment by ID
router.route("/:id").get(CommentController.getCommentById);

// Update a comment (only allowed for 'viewer' or 'admin' roles)
router
  .route("/:id")
  .put(authorizeRoles("viewer", "admin"), CommentController.updateComment);

// Delete a comment (only allowed for 'user' or 'admin' roles)
router
  .route("/:id")
  .delete(authorizeRoles("viewer", "admin"), CommentController.deleteComment);

// Flag a comment (only allowed for 'admin' role)
router
  .route("/:id/flag")
  .post(authorizeRoles("admin"), CommentController.flagComment);

// Approve a comment (only allowed for 'admin' role)
router
  .route("/:id/approve")
  .post(authorizeRoles("admin"), CommentController.approveComment);

// Restore a deleted comment (only allowed for 'admin' role)
router
  .route("/:id/restore")
  .post(authorizeRoles("admin"), CommentController.restoreDeletedComment);

// ----------------------------- Admin-only Routes ----------------------------

// Get reported comments (only allowed for 'admin' role)
router
  .route("/reported")
  .get(authorizeRoles("admin"), CommentController.getReportedComments);

// Get flagged comments (only allowed for 'admin' role)
router
  .route("/flagged")
  .get(authorizeRoles("admin"), CommentController.getFlaggedComments);

export default router;
