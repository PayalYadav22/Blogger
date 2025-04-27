import asyncHandler from "../../middleware/asyncHandler.middleware.js";
import User from "../../models/user.model.js";

const UserController = {
  getLoggedInUser: asyncHandler(async (req, res) => {}),
  updateUserProfile: asyncHandler(async (req, res) => {}),
  changeUserPassword: asyncHandler(async (req, res) => {}),
  updateUserAvatar: asyncHandler(async (req, res) => {}),
  getUserProfile: asyncHandler(async (req, res) => {}),
  updateUserPreferences: asyncHandler(async (req, res) => {}),
  deactivateUserAccount: asyncHandler(async (req, res) => {}),
  getMyPosts: asyncHandler(async (req, res) => {}),
  getMyComments: asyncHandler(async (req, res) => {}),
  getMyBookmarks: asyncHandler(async (req, res) => {}),
  getMyLikes: asyncHandler(async (req, res) => {}),
  getMySubscription: asyncHandler(async (req, res) => {}),
  updateMySubscription: asyncHandler(async (req, res) => {}),
  searchUsers: asyncHandler(async (req, res) => {}),
  getPopularUsers: asyncHandler(async (req, res) => {}),
  getMyActivity: asyncHandler(async (req, res) => {}),
};

export default UserController;
