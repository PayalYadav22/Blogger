import Joi from "joi";
import { StatusCodes } from "http-status-codes";
import ApiError from "../utils/apiError.js";

const validate = (schema, source = "body") => {
  return (req, res, next) => {
    const { error } = schema.validate(req[source], {
      abortEarly: false,
      allowUnknown: true,
      stripUnknown: true,
    });

    if (error) {
      const errorMessages = error.details.map((detail) => detail.message);
      return next(new ApiError(StatusCodes.BAD_REQUEST, errorMessages));
    }

    next();
  };
};

export default validate;
