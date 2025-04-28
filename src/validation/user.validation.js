import Joi from "joi";

export const registerValidUser = Joi.object({
  email: Joi.string()
    .email({ tlds: { allow: false } })
    .required()
    .messages({
      "string.email": "Email must be a valid email address",
      "any.required": "Email is required",
    }),

  userName: Joi.string().min(3).max(50).required().messages({
    "string.min": "Username must be at least 3 characters",
    "string.max": "Username cannot exceed 50 characters",
    "any.required": "Username is required",
  }),

  fullName: Joi.string().min(3).max(100).required().messages({
    "string.min": "Full name must be at least 3 characters",
    "string.max": "Full name cannot exceed 100 characters",
    "any.required": "Full name is required",
  }),

  phone: Joi.string()
    .pattern(/^[0-9]{10}$/)
    .required()
    .messages({
      "string.pattern.base": "Phone number must be 10 digits",
      "any.required": "Phone number is required",
    }),

  password: Joi.string()
    .min(8)
    .pattern(
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/
    )
    .required()
    .messages({
      "string.min": "Password must be at least 8 characters",
      "string.pattern.base":
        "Password must include 1 lowercase, 1 uppercase, 1 number, and 1 symbol",
      "any.required": "Password is required",
    }),

  bio: Joi.string().max(500).optional().messages({
    "string.max": "Bio cannot exceed 500 characters",
  }),

  gender: Joi.string().valid("male", "female", "trans").optional().messages({
    "any.only": "Gender must be one of male, female, or trans",
  }),

  dateOfBirth: Joi.date().less("now").optional().messages({
    "date.less": "Date of birth must be in the past",
  }),

  socialLinks: Joi.object({
    website: Joi.string().uri().messages({
      "string.uri": "Website must be a valid URL",
    }),
    twitter: Joi.string().uri().messages({
      "string.uri": "Twitter must be a valid URL",
    }),
    github: Joi.string().uri().messages({
      "string.uri": "GitHub must be a valid URL",
    }),
  })
    .optional()
    .allow(null)
    .messages({
      "object.base": "Social links must be an object",
    }),
}).options({
  abortEarly: false,
  allowUnknown: false,
});
