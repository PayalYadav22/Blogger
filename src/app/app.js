/**
 * @copyright 2025 Payal Yadav
 * @license Apache-2.0
 */

import express from "express";
import cookieParser from "cookie-parser";
import cors from "cors";
import helmet from "helmet";
import compression from "compression";

import { CORS_ORIGIN } from "../constants/constant.config.js";
import router from "../routes/router.js";
import errorHandler from "../middleware/errorHandler.error.js";
import notFound from "../middleware/notFound.middleware.js";

const app = express();

// Cookie Parser
app.use(cookieParser());

// // Security Middleware
app.use(helmet());

// Enable CORS
app.use(
  cors({
    origin: CORS_ORIGIN,
    credentials: true,
  })
);

// Data Parsing
app.use(express.json({ limit: "16kb" }));
app.use(express.urlencoded({ extended: true, limit: "16kb" }));

// Gzip Compression
app.use(compression());

// Serve Static Files
app.use(express.static("./public"));

// API Routes
app.use("/api/v1", router);

// Error Handler
app.use(errorHandler);

// Handle 404 Routes
app.use(notFound);

export default app;
