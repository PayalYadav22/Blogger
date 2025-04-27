import asynHandler from "../../middleware/asyncHandler.middleware.js";

const AdminController = {
  getAllUsers: asynHandler((req, res) => {}),
  getUser: asynHandler((req, res) => {}),
  updateUser: asynHandler((req, res) => {}),
  suspendUser: asynHandler((req, res) => {}),
  unsuspendUser: asynHandler((req, res) => {}),
  promoteUser: asynHandler((req, res) => {}),
  deleteUser: asynHandler((req, res) => {}),
  getReportedUsers: asynHandler((req, res) => {}),
  warnUser: asynHandler((req, res) => {}),
};

export default AdminController;
