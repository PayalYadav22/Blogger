/**
 * @copyright 2025 Payal Yadav
 * @license Apache-2.0
 */

import otpGenerator from "otp-generator";

const generateOTP = (
  length = 6,
  includeUpperCase = true,
  includeSpecialChars = true,
  includeDigits = true
) => {
  const options = {
    upperCase: includeUpperCase,
    specialChars: includeSpecialChars,
    digits: includeDigits,
  };

  const otp = otpGenerator.generate(length, options);
  return otp;
};

export default generateOTP;
