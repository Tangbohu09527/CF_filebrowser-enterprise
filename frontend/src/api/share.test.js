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

function expectSerializedFalseCapabilities(body) {
  const payload = JSON.parse(body);
  expect(Object.keys(payload.configuredCapabilities).sort()).toEqual([...CAPABILITY_KEYS].sort());
  expect(payload.configuredCapabilities).toStrictEqual(ALL_FALSE);
  for (const key of CAPABILITY_KEYS) {
    expect(Object.hasOwn(payload.configuredCapabilities, key)).toBe(true);
  }
  expect(payload).toMatchObject({
    disableDownload: true,
    disableThumbnails: true,
    disableFileViewer: true,
    allowCreate: false,
    allowModify: false,
    allowDelete: false,
    allowReplacements: false,
  });
}

beforeEach(() => {
  vi.clearAllMocks();
  mocks.fetchJSON.mockResolvedValue({ hash: "created-share" });
});

describe("Share configured capability request serialization", () => {
  it("keeps all nine explicit false values in a create payload", async () => {
    await shareApi.create({
      hash: "",
      path: "/docs/",
      source: "default",
      configuredCapabilities: { ...ALL_FALSE },
    });

    const [path, request] = mocks.fetchJSON.mock.calls[0];
    expect(path).toBe("/api/share");
    expect(request.method).toBe("POST");
    expectSerializedFalseCapabilities(request.body);
  });

  it("keeps all nine explicit false values in an update payload", async () => {
    await shareApi.create({
      hash: "existing-share",
      path: "/docs/",
      source: "default",
      configuredCapabilities: { ...ALL_FALSE },
    });

    const request = mocks.fetchJSON.mock.calls[0][1];
    const payload = JSON.parse(request.body);
    expect(payload.hash).toBe("existing-share");
    expectSerializedFalseCapabilities(request.body);
  });
});
