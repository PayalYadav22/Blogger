import express from "express";
import AdminController from "../controllers/admin/admin.controller.js";
import authenticate from "../middleware/authenticate.middleware.js";
import authorizeRoles from "../middleware/authorizeRoles.middleware.js";

const router = express.Router();

router.use(authenticate);
router.use(authorizeRoles("admin"));

// GET all users (with optional filters & search)
router.get("/users", AdminController.getAllUsers);

// GET reported users
router.get("/reported-users", AdminController.getReportedUsers);

// GET single user by ID
router.get("/users/:id", AdminController.getUser);

// PUT update user by ID
router.patch("/users/:id", AdminController.updateUser);

// PATCH suspend user
router.patch("/users/:id/suspend", AdminController.suspendUser);

// PATCH unsuspend user
router.patch("/users/:id/unsuspend", AdminController.unsuspendUser);

// PATCH promote user (e.g., to admin, moderator, etc.)
router.patch("/users/:id/promote", AdminController.promoteUser);

// DELETE user (soft or hard delete depending on your model)
router.delete("/users/:id", AdminController.deleteUser);

// POST warn a user
router.post("/users/:id/warn", AdminController.warnUser);

export default router;
