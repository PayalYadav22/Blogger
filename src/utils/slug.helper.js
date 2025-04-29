// models/helpers/slug.helper.js
import slugify from "slugify";
import { nanoid } from "nanoid";
import SlugAudit from "../models/slugAudit.model.js";
import Post from "../models/post.model.js";

export const generateUniqueSlug = async (title, currentId = null) => {
  const baseSlug = slugify(title.trim(), { lower: true, strict: true });
  let slug = baseSlug;
  const usedSlugs = new Set();

  let exists = await Post.exists({ slug, _id: { $ne: currentId } });
  while (exists || usedSlugs.has(slug)) {
    slug = `${baseSlug}-${nanoid(6)}`;
    usedSlugs.add(slug);
    exists = await Post.exists({ slug, _id: { $ne: currentId } });
  }

  return slug;
};

export const logSlugAudit = async (postId, oldSlug, newSlug) => {
  if (oldSlug !== newSlug) {
    await SlugAudit.create({ post: postId, oldSlug, newSlug });
  }
};
