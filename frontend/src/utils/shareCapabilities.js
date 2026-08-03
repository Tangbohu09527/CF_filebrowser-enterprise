export const SHARE_CAPABILITY_KEYS = Object.freeze([
  "browse",
  "preview",
  "download",
  "thumbnail",
  "viewer",
  "create",
  "modify",
  "delete",
  "replace",
]);

export const SHARE_CAPABILITY_LABEL_KEYS = Object.freeze({
  browse: "settings.permissions.browse",
  preview: "settings.permissions.preview",
  download: "settings.permissions.download",
  thumbnail: "profileSettings.showThumbnails",
  viewer: "profileSettings.fileViewerOptions",
  create: "settings.permissions.create",
  modify: "settings.permissions.modify",
  delete: "settings.permissions.delete",
  replace: "general.replace",
});

/**
 * @typedef {object} ShareCapabilities
 * @property {boolean} browse
 * @property {boolean} preview
 * @property {boolean} download
 * @property {boolean} thumbnail
 * @property {boolean} viewer
 * @property {boolean} create
 * @property {boolean} modify
 * @property {boolean} delete
 * @property {boolean} replace
 */

/**
 * @returns {ShareCapabilities}
 */
export function defaultShareCapabilities() {
  return {
    browse: true,
    preview: true,
    download: true,
    thumbnail: true,
    viewer: true,
    create: false,
    modify: false,
    delete: false,
    replace: false,
  };
}

/**
 * Return all capability keys as explicit booleans. Only the literal value true
 * enables a capability.
 *
 * @param {unknown} value
 * @returns {ShareCapabilities}
 */
export function normalizeShareCapabilities(value) {
  const capabilities = value !== null && typeof value === "object" ? value : {};

  return {
    browse: capabilities.browse === true,
    preview: capabilities.preview === true,
    download: capabilities.download === true,
    thumbnail: capabilities.thumbnail === true,
    viewer: capabilities.viewer === true,
    create: capabilities.create === true,
    modify: capabilities.modify === true,
    delete: capabilities.delete === true,
    replace: capabilities.replace === true,
  };
}

/**
 * @param {{ configuredCapabilities?: unknown, effectiveCapabilities?: unknown } | null | undefined} share
 * @returns {{ key: string, enabled: boolean, configured: boolean, reduced: boolean }[]}
 */
export function effectiveCapabilityItems(share) {
  const configured = normalizeShareCapabilities(share?.configuredCapabilities);
  const effective = normalizeShareCapabilities(share?.effectiveCapabilities);

  return SHARE_CAPABILITY_KEYS.map((key) => ({
    key,
    enabled: effective[key],
    configured: configured[key],
    reduced: configured[key] === true && effective[key] === false,
  }));
}

/**
 * @param {{ configuredCapabilities?: unknown, effectiveCapabilities?: unknown } | null | undefined} share
 * @returns {boolean}
 */
export function hasCapabilityReduction(share) {
  return effectiveCapabilityItems(share).some((item) => item.reduced);
}

/**
 * @param {{ effectiveCapabilities?: unknown } | null | undefined} share
 * @returns {boolean}
 */
export function hasAnyEffectiveCapability(share) {
  const effective = normalizeShareCapabilities(share?.effectiveCapabilities);
  return SHARE_CAPABILITY_KEYS.some((key) => effective[key]);
}

/**
 * @param {{ effectiveCapabilities?: unknown } | null | undefined} share
 * @param {string} key
 * @returns {boolean}
 */
export function hasEffectiveCapability(share, key) {
  if (!SHARE_CAPABILITY_KEYS.includes(key)) {
    return false;
  }

  return normalizeShareCapabilities(share?.effectiveCapabilities)[key];
}
