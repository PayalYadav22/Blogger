/**
 * @copyright 2025 Payal Yadav
 * @license Apache-2.0
 */

import mongoose from "mongoose";
import logger from "../logger/winston.logger.js";
import User from "../models/user.model.js";

const connectDB = async (url, dbName) => {
  try {
    await mongoose.connect(`${url}/${dbName}`);
    logger.info(`\n MongoDB Connected!`);
  } catch (error) {
    logger.error(`Database connection failed : ${error}`);
    process.exit(1);
  }
};

export default connectDB;
