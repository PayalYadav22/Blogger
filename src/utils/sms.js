/**
 * @copyright 2025 Payal Yadav
 * @license Apache-2.0
 */

import twilio from "twilio";
import {
  TWILIO_ACCOUNT_SID,
  TWILIO_AUTH_TOKEN,
  TWILIO_PHONE_NUMBER,
} from "../constants/constant.config.js";
import logger from "../logger/winston.logger.js";
import ApiError from "./apiError.js";
import { StatusCodes } from "http-status-codes";

const client = new twilio(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN);

const sendSms = async ({ to, body }) => {
  try {
    if (!to) {
      throw new ApiError(
        StatusCodes.BAD_REQUEST,
        "Recipient phone number (to) is required"
      );
    }
    if (!body) {
      throw new ApiError(StatusCodes.BAD_REQUEST, "Message body is required");
    }
    const message = await client.messages.create({
      body,
      from: TWILIO_PHONE_NUMBER,
      to,
    });

    return message;
  } catch (error) {
    logger.error("Error sending SMS:", error);
    throw error;
  }
};

export default sendSms;
