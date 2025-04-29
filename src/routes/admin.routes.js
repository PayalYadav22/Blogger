import express from "express";
import AdminController from "../controllers/admin/admin.controller.js";
import authenticate from "../middleware/authenticate.middleware.js";
import authorizeRoles from "../middleware/authorizeRoles.middleware.js";

const router = express.Router();

// Middleware to authenticate and authorize admin access
router.use(authenticate);
router.use(authorizeRoles("admin"));

// Bulk & Reported Users
router.route("/users").get(AdminController.getAllUsers);
router.route("/reported-users").get(AdminController.getReportedUsers);

// Single User Operations
router
  .route("/users/:id")
  .get(AdminController.getUser)
  .patch(AdminController.updateUser)
  .delete(AdminController.deleteUser);

// Suspension & Role Management
router.route("/users/:id/suspend").patch(AdminController.suspendUser);
router.route("/users/:id/unsuspend").patch(AdminController.unsuspendUser);
router.route("/users/:id/promote").patch(AdminController.promoteUser);

// User Warnings
router.route("/users/:id/warn").post(AdminController.warnUser);

export default router;
