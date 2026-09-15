import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  shared: false,
  state: {
    req: {},
    user: { disableViewingExt: [] },
    shareInfo: { hash: "preview-share", subPath: "/", token: "fixture-token" },
    isSafari: false,
  },
  globalVars: {
    muPdfAvailable: true,
    exiftoolAvailable: true,
    mediaAvailable: true,
    enableHeicConversion: true,
  },
  getPreviewURL: vi.fn((source, path) =>
    `https://preview.test/api/resources/preview?${new URLSearchParams({ source, path })}`),
  getPreviewURLPublic: vi.fn((path, size) =>
    `https://preview.test/public/api/resources/preview?${new URLSearchParams({ path, size })}`),
  getDownloadURL: vi.fn((source, path, inline = false) =>
    `https://preview.test/api/resources/download?${new URLSearchParams({ source, path, inline: String(inline) })}`),
  getDownloadURLPublic: vi.fn((_share, paths, inline = false) =>
    `https://preview.test/public/api/resources/download?${new URLSearchParams({ path: paths[0], inline: String(inline) })}`),
}));

vi.mock("@/api", () => ({
  resourcesApi: {
    getPreviewURL: mocks.getPreviewURL,
    getPreviewURLPublic: mocks.getPreviewURLPublic,
    getDownloadURL: mocks.getDownloadURL,
    getDownloadURLPublic: mocks.getDownloadURLPublic,
  },
  mediaApi: {},
}));
vi.mock("@/store", () => ({
  state: mocks.state,
  getters: { isShare: () => mocks.shared },
  mutations: {},
}));
vi.mock("@/utils", () => ({ url: { removeTrailingSlash: path => path.replace(/\/+$/, "") || "/" } }));
vi.mock("@/utils/constants", () => ({ globalVars: mocks.globalVars }));
vi.mock("@/utils/subtitles", () => ({ convertToVTT: vi.fn(), getSubtitleFormatExtension: vi.fn() }));
vi.mock("@/utils/previewPlaybackQueueNav.js", () => ({ replaceRouteForPlaybackQueueStep: vi.fn() }));
vi.mock("@/components/files/ExtendedImage.vue", () => ({ default: {} }));
vi.mock("@/views/files/plyrViewer.vue", () => ({ default: {} }));
vi.mock("@/components/LoadingSpinner.vue", () => ({ default: {} }));

import Preview from "./Preview.vue";

function viewerURL(name, type) {
  mocks.state.req = { name, type, source: "documents", path: "/" + name, modified: "2026-01-01T00:00:00Z" };
  const context = { pdfConvertable: Preview.computed.pdfConvertable.call({}) };
  return new URL(Preview.computed.raw.call(context));
}

beforeEach(() => {
  vi.clearAllMocks();
  mocks.shared = false;
  mocks.state.isSafari = false;
  mocks.state.user.disableViewingExt = [];
  Object.assign(mocks.globalVars, {
    muPdfAvailable: true,
    exiftoolAvailable: true,
    mediaAvailable: true,
    enableHeicConversion: true,
  });
});

describe("converted document viewer URLs", () => {
  for (const [name, type] of [
    ["sheet.xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"],
    ["slides.pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation"],
    ["drawing.svg", "image/svg+xml"],
  ]) {
    it.each([false, true])(`requests the derived xlarge image for ${name} (share=%s)`, shared => {
      mocks.shared = shared;
      const requested = viewerURL(name, type);
      expect(requested.pathname).toBe(shared ? "/public/api/resources/preview" : "/api/resources/preview");
      expect(requested.searchParams.get("path")).toBe("/" + name);
      expect(requested.searchParams.get("size")).toBe("xlarge");
      expect(mocks.getDownloadURL).not.toHaveBeenCalled();
      expect(mocks.getDownloadURLPublic).not.toHaveBeenCalled();
    });
  }

  it.each([false, true])("keeps the explicit document download action separate (share=%s)", shared => {
    mocks.shared = shared;
    viewerURL("sheet.xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
    const requested = new URL(Preview.computed.downloadUrl.call({}));
    expect(requested.pathname).toBe(shared ? "/public/api/resources/download" : "/api/resources/download");
    expect(requested.searchParams.get("path")).toBe("/sheet.xlsx");
    expect(requested.searchParams.get("inline")).toBe("false");
    expect(requested.searchParams.has("size")).toBe(false);
  });
});

describe("existing original-file viewer URL contracts", () => {
  for (const [name, type] of [
    ["picture.png", "image/png"],
    ["photo.jpg", "image/jpeg"],
    ["document.pdf", "application/pdf"],
    ["notes.txt", "text/plain"],
  ]) {
    it.each([false, true])(`preserves inline original reads for ${name} (share=%s)`, shared => {
      mocks.shared = shared;
      const requested = viewerURL(name, type);
      expect(requested.pathname).toBe(shared ? "/public/api/resources/download" : "/api/resources/download");
      expect(requested.searchParams.get("path")).toBe("/" + name);
      expect(requested.searchParams.get("inline")).toBe("true");
      expect(mocks.getPreviewURL).not.toHaveBeenCalled();
      expect(mocks.getPreviewURLPublic).not.toHaveBeenCalled();
    });
  }

  for (const [name, type] of [["photo.heic", "image/heic"], ["camera.cr2", "image/x-canon-cr2"]]) {
    it.each([false, true])(`preserves the original preview selection for ${name} (share=%s)`, shared => {
      mocks.shared = shared;
      const requested = viewerURL(name, type);
      expect(requested.pathname).toBe(shared ? "/public/api/resources/preview" : "/api/resources/preview");
      expect(requested.searchParams.get("size")).toBe("original");
      expect(mocks.getDownloadURL).not.toHaveBeenCalled();
      expect(mocks.getDownloadURLPublic).not.toHaveBeenCalled();
    });
  }

  it.each([false, true])("preserves Safari's native HEIC original read (share=%s)", shared => {
    mocks.shared = shared;
    mocks.state.isSafari = true;
    const requested = viewerURL("photo.heic", "image/heic");
    expect(requested.pathname).toBe(shared ? "/public/api/resources/download" : "/api/resources/download");
    expect(requested.searchParams.get("inline")).toBe("true");
    expect(mocks.getPreviewURL).not.toHaveBeenCalled();
    expect(mocks.getPreviewURLPublic).not.toHaveBeenCalled();
  });
});
