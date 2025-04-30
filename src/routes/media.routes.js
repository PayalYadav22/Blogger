import express from "express";
import MediaController from "../controllers/media/media.controller.js";
import authenticate from "../middleware/authenticate.middleware.js";
import authorizeRoles from "../middleware/authorizeRoles.middleware.js";

const router = express.Router();

// Apply authentication middleware
router.use(authenticate);

// Get all media
router.get("/media", MediaController.getAllMedia);

// Get single media
router.get("/media/:mediaId", MediaController.getSingleMedia);

// Add comment to media
router.post("/media/:mediaId/comment", MediaController.addComment);

// Get comments for media
router.get("/media/:mediaId/comments", MediaController.getComments);

// Add rating to media
router.post("/media/:mediaId/rating", MediaController.addRating);

// Search media by tags
router.get("/media/search", MediaController.searchMediaByTags);

// Filter media by type
router.get("/media/filter/type", MediaController.filterMediaByType);

// Filter media by status
router.get("/media/filter/status", MediaController.filterMediaByStatus);

// Filter media by access control
router.get(
  "/media/filter/access-control",
  MediaController.filterMediaByAccessControl
);

// Filter media by expiry
router.get("/media/filter/expiry", MediaController.filterMediaByExpiry);

// Get expired media
router.get("/media/expired", MediaController.getExpiredMedia);

// Admin routes - Authorization middleware for these actions
router.use(authorizeRoles("admin"));

// Create media
// (Add the route for creating media if necessary)

// Update media
router.put("/media/:mediaId", MediaController.updateMedia);

// Delete media
router.delete("/media/:mediaId", MediaController.deleteMedia);

// Approve media
router.put("/media/:mediaId/approve", MediaController.approveMedia);

// Reject media
router.put("/media/:mediaId/reject", MediaController.rejectMedia);

// Set media to pending status
router.put("/media/:mediaId/pending", MediaController.setMediaToPending);

// Start processing media
router.put(
  "/media/:mediaId/start-processing",
  MediaController.startProcessingMedia
);

// Complete processing media
router.put(
  "/media/:mediaId/complete-processing",
  MediaController.completeProcessingMedia
);

// Log media operation
router.post("/media/:mediaId/log", MediaController.logMediaOperation);

// Change media access control
router.put(
  "/media/:mediaId/access-control",
  MediaController.changeAccessControl
);

// Set media expiry date
router.put("/media/:mediaId/expiry", MediaController.setMediaExpiry);

// Soft delete media
router.put("/media/:mediaId/soft-delete", MediaController.softDeleteMedia);

// Get all media for admin
router.get("/admin/media", MediaController.getAllMediaForAdmin);

// Bulk approve media
router.put("/media/bulk-approve", MediaController.bulkApproveMedia);

// Bulk reject media
router.put("/media/bulk-reject", MediaController.bulkRejectMedia);

export default router;
