/**
 * @copyright 2025 Payal Yadav
 * @license Apache-2.0
 */

import express from "express";
import cookieParser from "cookie-parser";
import cors from "cors";
import helmet from "helmet";
import compression from "compression";
import mongoSanitize from "express-mongo-sanitize";
import morgan from "morgan";
import rateLimit from "express-rate-limit";

import { CORS_ORIGIN, BODY_SIZE_LIMIT } from "../constants/constant.config.js";
import router from "../routes/router.js";
import errorHandler from "../middleware/errorHandler.error.js";
import notFound from "../middleware/notFound.middleware.js";

const app = express();

/**
 * Security Middleware Setup
 */
app.use(helmet());
app.use(
  helmet.contentSecurityPolicy({ directives: { defaultSrc: ["'self'"] } })
);

/**
 * CORS Middleware Setup
 */
app.use(
  cors({
    origin: CORS_ORIGIN,
    credentials: true,
  })
);

/**
 * Cookie Parser Setup
 */
app.use(cookieParser());

/**
 * Body Parsers Setup
 */
app.use(express.json({ limit: BODY_SIZE_LIMIT || "16kb" }));
app.use(
  express.urlencoded({ extended: true, limit: BODY_SIZE_LIMIT || "16kb" })
);

/**
 * Logging Middleware (for development)
 */
if (process.env.NODE_ENV !== "production") {
  app.use(morgan("dev"));
}

/**
 * Rate Limiting Middleware Setup
 */
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: "Too many requests from this IP, please try again after 15 minutes",
});

app.use("/api/v1", apiLimiter);

/**
 * Compression Middleware Setup
 */
app.use(compression());

/**
 * Static Files Middleware Setup
 */
app.use(express.static("./public"));

/**
 * Routes Setup
 */
app.use("/api/v1", router);

/**
 * Error Handling Middleware Setup
 */
app.use(notFound);
app.use(errorHandler);

export default app;
