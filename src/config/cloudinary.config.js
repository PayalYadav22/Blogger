import { v2 as cloudinary } from "cloudinary";
import logger from "../logger/winston.logger.js";
import fs from "fs/promises";
import {
  CLOUDINARY_NAME,
  CLOUDINARY_API_KEY,
  CLOUDINARY_API_SECRET,
} from "../constants/constant.config.js";

cloudinary.config({
  cloud_name: CLOUDINARY_NAME,
  api_key: CLOUDINARY_API_KEY,
  api_secret: CLOUDINARY_API_SECRET,
});

const uploadFileToCloudinary = async (localFilePath) => {
  if (!localFilePath) return null;
  const response = await cloudinary.uploader.upload(localFilePath, {
    resource_type: "auto",
  });
  if (!response) {
    logger.error("Failed to upload image from Cloudinary:", error);
  }
  await fs.unlink(localFilePath);
  return response;
};

const deleteFileFromCloudinary = async (publicId) => {
  try {
    return await cloudinary.uploader.destroy(publicId);
  } catch (error) {
    logger.error("Error deleting image from Cloudinary:", error);
    throw error;
  }
};

export { uploadFileToCloudinary, deleteFileFromCloudinary };
