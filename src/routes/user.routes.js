import express from "express";
import UserController from "../controllers/users/users.controller.js";
import authenticate from "../middleware/authenticate.middleware.js";
import require2FA from "../middleware/require2FA.middleware.js";
import authorizeRoles from "../middleware/authorizeRoles.middleware.js";

const router = express.Router();

// ================= Global Middlewares =================

// All user routes require authentication and 2FA
router.use(authenticate);
router.use(require2FA);

// ================= User Profile Routes =================

// Accessible to all logged-in users (any role)
router
  .route("/me")
  .get(UserController.getLoggedInUser)
  .patch(UserController.updateUserProfile);
router.route("/change-password").patch(UserController.changeUserPassword);
router.put("/me/avatar", UserController.updateUserAvatar);

// ================= User Content Routes =================

// Posts, comments, bookmarks, likes
router.get("/me/posts", UserController.getMyPosts);
router.get("/me/comments", UserController.getMyComments);
router.get("/me/bookmarks", UserController.getMyBookmarks);
router.get("/me/likes", UserController.getMyLikes);

// ================= Subscription Routes =================

// Subscription management
router.get(
  "/me/subscription",
  authorizeRoles("admin", "subscriber"),
  UserController.getMySubscription
);
router.put(
  "/me/subscription",
  authorizeRoles("admin", "subscriber"),
  UserController.updateMySubscription
);

// ================= Other Settings =================

// Preferences update
router.put("/me/preferences", UserController.updateUserPreferences);

// Deactivate own account
router.delete("/me/deactivate", UserController.deactivateUserAccount);

// ================= Public User Routes =================

// Anyone logged in can search or view public profiles
router.get("/search", UserController.searchUsers);
router.get("/popular", UserController.getPopularUsers);
router.get("/:userId", UserController.getUserProfile);

export default router;
