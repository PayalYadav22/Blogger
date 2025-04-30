import express from "express";
import LikeController from "../controllers/like/like.controller.js";
import authenticate from "../middleware/authenticate.middleware.js";

const router = express.Router();

// Apply authentication middleware
router.use(authenticate);

// Toggle like on a post
router.put("/like/:postId", LikeController.toggleLike);

// Get all likes on a post
router.get("/likes/:postId", LikeController.getPostLikes);

// Get all posts liked by a user
router.get("/user/:userId/liked-posts", LikeController.getUserLikedPosts);

// Check if a specific user liked a specific post
router.get(
  "/user/:userId/like-status/:postId",
  LikeController.isPostLikedByUser
);

// Count the number of likes on a post
router.get("/likes/count/:postId", LikeController.countPostLikes);

export default router;
