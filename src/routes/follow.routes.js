import express from "express";
import FollowController from "../controllers/follow/follow.controller.js";

const router = express.Router();

// Route to follow or unfollow a user
router.post("/follow", FollowController.followUser);

// Route to unfollow a user
router.post("/unfollow", FollowController.unfollowUser);

// Route to check if the user is following another user
router.get("/check-following", FollowController.checkIfFollowing);

// Route to get all followers of a user
router.get("/:userId/followers", FollowController.getFollowers);

// Route to get all users that a user is following
router.get("/:userId/following", FollowController.getFollowing);

export default router;
