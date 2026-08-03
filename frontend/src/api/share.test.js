import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  adjustedData: vi.fn((value) => value),
  fetchJSON: vi.fn(),
  fetchURL: vi.fn(),
  getApiPath: vi.fn(() => "/api/share"),
  showError: vi.fn(),
}));

vi.mock("./utils", () => ({
  adjustedData: mocks.adjustedData,
  fetchJSON: mocks.fetchJSON,
  fetchURL: mocks.fetchURL,
}));

vi.mock("@/utils/url.js", () => ({
  getApiPath: mocks.getApiPath,
  getPublicApiPath: vi.fn(),
}));

vi.mock("@/notify", () => ({
  notify: { showError: mocks.showError },
}));

import * as shareApi from "./share.js";

const CAPABILITY_KEYS = [
  "browse",
  "preview",
  "download",
  "thumbnail",
  "viewer",
  "create",
  "modify",
  "delete",
  "replace",
];
const ALL_FALSE = Object.fromEntries(CAPABILITY_KEYS.map((key) => [key, false]));
const ALL_TRUE = Object.fromEntries(CAPABILITY_KEYS.map((key) => [key, true]));

function expectSerializedCapabilities(body, expected) {
  const payload = JSON.parse(body);
  expect(Object.keys(payload.configuredCapabilities).sort()).toEqual([...CAPABILITY_KEYS].sort());
  expect(payload.configuredCapabilities).toStrictEqual(expected);
  for (const key of CAPABILITY_KEYS) {
    expect(Object.hasOwn(payload.configuredCapabilities, key)).toBe(true);
    expect(typeof payload.configuredCapabilities[key]).toBe("boolean");
  }
  expect(payload).toMatchObject({
    disableDownload: !expected.download,
    disableThumbnails: !expected.thumbnail,
    disableFileViewer: !expected.viewer,
    allowCreate: expected.create,
    allowModify: expected.modify,
    allowDelete: expected.delete,
    allowReplacements: expected.replace,
  });
}

beforeEach(() => {
  vi.clearAllMocks();
  mocks.fetchJSON.mockResolvedValue({ hash: "created-share" });
});

describe("Share configured capability request serialization", () => {
  it("derives normal Share Browse/Preview while preserving every other explicit false", async () => {
    await shareApi.create({
      hash: "",
      path: "/docs/",
      source: "default",
      shareType: "normal",
      configuredCapabilities: { ...ALL_FALSE },
    });

    const [path, request] = mocks.fetchJSON.mock.calls[0];
    expect(path).toBe("/api/share");
    expect(request.method).toBe("POST");
    expectSerializedCapabilities(request.body, { ...ALL_FALSE, browse: true });
  });

  it("derives Preview from Thumbnail/Viewer for an update payload", async () => {
    await shareApi.create({
      hash: "existing-share",
      path: "/docs/",
      source: "default",
      shareType: "normal",
      configuredCapabilities: { ...ALL_FALSE, preview: false, viewer: true },
    });

    const request = mocks.fetchJSON.mock.calls[0][1];
    const payload = JSON.parse(request.body);
    expect(payload.hash).toBe("existing-share");
    expectSerializedCapabilities(request.body, {
      ...ALL_FALSE,
      browse: true,
      preview: true,
      viewer: true,
    });
  });

  it("cannot serialize upload Create false while retaining configurable values", async () => {
    await shareApi.create({
      hash: "upload-share",
      path: "/uploads/",
      source: "default",
      shareType: "upload",
      configuredCapabilities: { ...ALL_TRUE, create: false },
    });

    const request = mocks.fetchJSON.mock.calls[0][1];
    expectSerializedCapabilities(request.body, {
      ...ALL_TRUE,
      browse: false,
      preview: false,
      create: true,
    });
  });
});
