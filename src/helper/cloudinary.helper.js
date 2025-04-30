import ffmpeg from "fluent-ffmpeg";

function isValidCloudinaryURL(url) {
  const cloudinaryDomain = "res.cloudinary.com";
  const urlObj = new URL(url);
  return urlObj.hostname === cloudinaryDomain;
}

function validateVideoMetadata(videoUrl) {
  return new Promise((resolve, reject) => {
    ffmpeg.ffprobe(videoUrl, (err, metadata) => {
      if (err) {
        reject("Error extracting video metadata");
      }
      if (metadata.format.duration > 0) {
        resolve(true);
      } else {
        reject("Invalid video duration");
      }
    });
  });
}

async function validateMedia(url) {
  if (!isValidCloudinaryURL(url)) {
    return "Invalid media source";
  }
  const videoExtensions = [".mp4", ".mov", ".avi"];
  const audioExtensions = [".mp3", ".wav", ".ogg"];
  const urlExtension = url.split(".").pop().toLowerCase();
  if (videoExtensions.includes(urlExtension)) {
    try {
      await validateVideoMetadata(url);
      return "Valid video";
    } catch (error) {
      return "Invalid video metadata";
    }
  }
  if (audioExtensions.includes(urlExtension)) {
    try {
      await validateAudioMetadata(url);
      return "Valid audio";
    } catch (error) {
      return "Invalid audio metadata";
    }
  }
  return "Unsupported media format";
}

export { isValidCloudinaryURL, validateVideoMetadata, validateMedia };
