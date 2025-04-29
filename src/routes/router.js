import express from "express";

import adminRoute from "./admin.routes.js";
import authRoute from "./auth.routes.js";
import socialRoute from "./social.routes.js";
import userRoute from "./user.routes.js";
import postRoute from "./post.routes.js";

const router = express.Router();

router.use("/admin", adminRoute);
router.use("/auth", authRoute);
router.use("/social", socialRoute);
router.use("/users", userRoute);
router.use("/posts", postRoute);

export default router;
