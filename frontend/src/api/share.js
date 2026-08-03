import { notify } from "@/notify";
import { deriveConfiguredShareCapabilities } from "@/utils/shareCapabilities.js";
import { getApiPath, getPublicApiPath } from "@/utils/url.js";
import { adjustedData, fetchJSON, fetchURL } from "./utils";


// ============================================================================
// SHARE MANAGEMENT API (permission-based authentication)
// ============================================================================

// List all shares
export async function list() {
  try {
    const apiPath = getApiPath("share/list");
    return await fetchJSON(apiPath);
  } catch (err) {
    notify.showError("Error listing shares");
    throw err;
  }
}

// Get share information
/**
 * @param {string} path
 * @param {string} source
 * @returns {Promise<any>}
 */
export async function get(path, source) {
  try {
    const params = { path, source };
    const apiPath = getApiPath("share", params);
    const data = await fetchJSON(apiPath);
    return adjustedData(data);
  } catch (err) {
    notify.showError("Error fetching share");
    throw err;
  }
}

// Remove/delete a share
/**
 * @param {string} hash
 * @returns {Promise<void>}
 */
export async function remove(hash) {
  try {
    const params = { hash };
    const apiPath = getApiPath("share", params);
    await fetchURL(apiPath, {
      method: "DELETE",
    });
  } catch (err) {
    notify.showError("Error deleting share");
    throw err;
  }
}

// Create a new share
/**
 * @param {Record<string, any>} bodyObj
 * @returns {Promise<Share>}
 */
export async function create(bodyObj = {}) {
  try {
    const payload = { ...(bodyObj || {}) };
    if (Object.hasOwn(payload, "configuredCapabilities")) {
      const capabilities = deriveConfiguredShareCapabilities(
        payload.configuredCapabilities,
        payload.shareType,
      );
      payload.configuredCapabilities = capabilities;
      payload.disableDownload = !capabilities.download;
      payload.disableThumbnails = !capabilities.thumbnail;
      payload.disableFileViewer = !capabilities.viewer;
      payload.allowCreate = capabilities.create;
      payload.allowModify = capabilities.modify;
      payload.allowDelete = capabilities.delete;
      payload.allowReplacements = capabilities.replace;
    }

    const apiPath = getApiPath("share");
    return await fetchJSON(apiPath, {
      method: "POST",
      body: JSON.stringify(payload),
    });
  } catch (err) {
    notify.showError("Error creating share");
    throw err;
  }
}

// Update share path
/**
 * @param {string} hash
 * @param {string} newPath
 * @returns {Promise<Share>}
 */
export async function updatePath(hash, newPath) {
  try {
    const apiPath = getApiPath("share");
    return await fetchJSON(apiPath, {
      method: "PATCH",
      body: JSON.stringify({ hash, path: newPath }),
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (err) {
    notify.showError("Error updating share path");
    throw err;
  }
}

/**
 * @typedef {import("@/utils/shareCapabilities.js").ShareCapabilities} ShareCapabilities
 */

/**
 * @typedef {object} Share
 * @property {string} hash
 * @property {string} shareURL
 * @property {string} downloadURL
 * @property {string} source
 * @property {string} path
 * @property {string} shareType
 * @property {number} expire
 * @property {string} status
 * @property {boolean} hasPassword
 * @property {ShareCapabilities} configuredCapabilities
 * @property {ShareCapabilities} effectiveCapabilities
 */

// ============================================================================
// PUBLIC API ENDPOINTS (hash-based authentication)
// ============================================================================

export async function getShareInfoPublic(hash) {
  try {
    const apiPath = getPublicApiPath('share/info', { hash: hash })
    const response = await fetch(apiPath)
    return response.json()
  } catch (err) {
    notify.showError('Error getting share info')
    throw err
  }
}
