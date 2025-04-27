import asynHandler from "../../middleware/asyncHandler.middleware.js";

const SocialController = {
  followUser: asynHandler((req, res) => {}),
  unfollowUser: asynHandler((req, res) => {}),
  getUserFollowers: asynHandler((req, res) => {}),
  getUserFollowing: asynHandler((req, res) => {}),
  blockUser: asynHandler((req, res) => {}),
  unblockUser: asynHandler((req, res) => {}),
  getBlockedUsers: asynHandler((req, res) => {}),
};

export default SocialController;
