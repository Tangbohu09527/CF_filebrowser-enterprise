import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => {
  const state = {
    prompts: [],
    sessionId: "SESSION-A",
    shareInfo: { hash: "", token: "" },
    sharePassword: "",
    user: { fileLoading: { downloadChunkSizeMb: 0 } },
  };

  return {
    adjustedData: vi.fn((value) => value),
    fetch: vi.fn(),
    fetchURL: vi.fn(),
    fileTreeFetchFilesPublic: vi.fn(),
    getApiPath: vi.fn(() => "/api/resources/download"),
    getPublicApiPath: vi.fn((route, params = {}) => {
      const query = new URLSearchParams();
      for (const [key, value] of Object.entries(params)) {
        if (value === "" || value === null || value === undefined || value === false) {
          continue;
        }
        const values = Array.isArray(value) ? value : [value];
        for (const entry of values) {
          query.append(key, String(entry));
        }
      }
      const encoded = query.toString();
      return `/public/api/${route}${encoded ? `?${encoded}` : ""}`;
    }),
    moveCopyPublic: vi.fn(),
    showError: vi.fn(),
    state,
    xmlHttpRequest: vi.fn(),
  };
});

vi.mock("@/store", () => ({
  state: mocks.state,
  getters: {
    permissions: vi.fn(() => ({})),
    shareHash: vi.fn(() => ""),
  },
  mutations: {
    showPrompt: vi.fn(),
  },
}));

vi.mock("@/notify", () => ({
  notify: { showError: mocks.showError },
}));

vi.mock("@/utils/constants", () => ({
  globalVars: {},
}));

vi.mock("@/utils/downloadManager", () => ({
  downloadManager: {},
}));

vi.mock("@/utils/url.js", () => ({
  getApiPath: mocks.getApiPath,
  getPublicApiPath: mocks.getPublicApiPath,
  goToItem: vi.fn(),
  joinPath: vi.fn((...parts) => parts.join("/")),
}));

vi.mock("./utils", () => ({
  adjustedData: mocks.adjustedData,
  fetchURL: mocks.fetchURL,
}));

vi.mock("@/store/eventBus", () => ({
  eventBus: { off: vi.fn(), on: vi.fn() },
}));

vi.mock("@/components/files/Icon.vue", () => ({ default: {} }));
vi.mock("@/components/LoadingSpinner.vue", () => ({ default: {} }));

vi.mock("@/api", () => ({
  resourcesApi: {
    fetchFilesPublic: (...args) => mocks.fileTreeFetchFilesPublic(...args),
    moveCopyPublic: mocks.moveCopyPublic,
  },
}));

import * as resourcesApi from "./resources.js";
import FileTree from "@/components/files/FileTree.vue";

const PASSWORD_A = "PASSWORD-A";
const PASSWORD_B = "PASSWORD-B";
const TOKEN_A = "TOKEN-A";
const TOKEN_B = "TOKEN-B";

function successfulResponse(data = { items: [] }) {
  return {
    headers: new Headers(),
    json: vi.fn().mockResolvedValue(data),
    ok: true,
    status: 200,
    statusText: "OK",
  };
}

function deferred() {
  let resolve;
  const promise = new Promise((resolvePromise) => {
    resolve = resolvePromise;
  });
  return { promise, resolve };
}

function setActiveShare(hash, password, token) {
  mocks.state.shareInfo = { hash, token };
  mocks.state.sharePassword = password;
}

function lastRequest() {
  const [rawURL, options = {}] = mocks.fetch.mock.calls.at(-1);
  return {
    headers: new Headers(options.headers || {}),
    options,
    url: new URL(rawURL, "https://example.test"),
  };
}

function expectNoCredentials(request, ...secrets) {
  expect(request.url.searchParams.has("token")).toBe(false);
  expect(request.headers.has("X-SHARE-PASSWORD")).toBe(false);
  expect(request.headers.has("X-Auth-Token")).toBe(false);
  expect(request.headers.has("Authorization")).toBe(false);
  expect(request.headers.has("Cookie")).toBe(false);
  expect(request.options.credentials).toBe("omit");
  expect(JSON.stringify(mocks.fetch.mock.calls.at(-1))).not.toContain(mocks.state.sessionId);
  for (const secret of secrets) {
    expect(JSON.stringify(mocks.fetch.mock.calls.at(-1))).not.toContain(secret);
  }
}

async function fetchFromFileTree(shareHash) {
  return FileTree.methods.fetchItems.call({
    isShare: true,
    shareHash,
    showFiles: true,
  }, "/");
}

beforeEach(() => {
  vi.clearAllMocks();
  setActiveShare("", "", "");
  mocks.fetch.mockResolvedValue(successfulResponse());
  mocks.fetchURL.mockResolvedValue(successfulResponse());
  mocks.fileTreeFetchFilesPublic.mockImplementation((...args) => (
    resourcesApi.fetchFilesPublic(...args)
  ));
  vi.stubGlobal("fetch", mocks.fetch);
  vi.stubGlobal("XMLHttpRequest", mocks.xmlHttpRequest);
  vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("hash-bound public Share credentials", () => {
  it("uses Share B in the URL without sending Share A credentials", async () => {
    setActiveShare("share-A", PASSWORD_A, TOKEN_A);

    await resourcesApi.fetchFilesPublic("/docs", "share-B", PASSWORD_A);

    const request = lastRequest();
    expect(request.url.searchParams.get("hash")).toBe("share-B");
    expectNoCredentials(request, PASSWORD_A, TOKEN_A);
  });

  it("does not send active Share credentials with an empty hash", async () => {
    setActiveShare("share-A", PASSWORD_A, TOKEN_A);

    await resourcesApi.fetchFilesPublic("/docs", "", PASSWORD_A);

    expectNoCredentials(lastRequest(), PASSWORD_A, TOKEN_A);
  });

  it("sends the active Share credentials for an exact hash match", async () => {
    setActiveShare("share-A", PASSWORD_A, TOKEN_A);

    await resourcesApi.fetchFilesPublic("/docs", "share-A", PASSWORD_A);

    const request = lastRequest();
    expect(request.url.searchParams.get("hash")).toBe("share-A");
    expect(request.url.searchParams.get("token")).toBe(TOKEN_A);
    expect(request.headers.get("X-SHARE-PASSWORD")).toBe(PASSWORD_A);
    expect(request.options.credentials).toBe("same-origin");
  });

  it("omits an empty password Header and empty token for a matching hash", async () => {
    setActiveShare("share-A", "", "");

    await resourcesApi.fetchFilesPublic("/docs", "share-A", PASSWORD_A);

    const request = lastRequest();
    expect(request.url.searchParams.has("token")).toBe(false);
    expect(request.headers.has("X-SHARE-PASSWORD")).toBe(false);
    expect(JSON.stringify(mocks.fetch.mock.calls.at(-1))).not.toContain(PASSWORD_A);
  });

  it("binds getItemsPublic token use to the requested hash", async () => {
    setActiveShare("share-A", PASSWORD_A, TOKEN_A);

    await resourcesApi.getItemsPublic("share-B", "/");
    expectNoCredentials(lastRequest(), PASSWORD_A, TOKEN_A);

    await resourcesApi.getItemsPublic("share-A", "/");
    const matchingRequest = lastRequest();
    expect(matchingRequest.url.searchParams.get("token")).toBe(TOKEN_A);
    expect(matchingRequest.options.credentials).toBe("same-origin");
  });

  it("binds moveCopyPublic X-Auth-Token use to the requested hash", async () => {
    setActiveShare("share-A", PASSWORD_A, TOKEN_A);
    const items = [{ from: "/from.txt", to: "/to.txt" }];

    await resourcesApi.moveCopyPublic("share-B", items);
    expectNoCredentials(lastRequest(), PASSWORD_A, TOKEN_A);

    await resourcesApi.moveCopyPublic("share-A", items);
    const matchingRequest = lastRequest();
    expect(matchingRequest.headers.get("X-Auth-Token")).toBe(TOKEN_A);
    expect(matchingRequest.options.credentials).toBe("same-origin");
  });

  it("keeps FileTree from combining its Share B route with Share A credentials", async () => {
    setActiveShare("share-A", PASSWORD_A, TOKEN_A);

    await fetchFromFileTree("share-B");

    expect(mocks.fileTreeFetchFilesPublic).toHaveBeenCalledWith(
      "/", "share-B", PASSWORD_A, false, false, true,
    );
    const request = lastRequest();
    expect(request.url.searchParams.get("hash")).toBe("share-B");
    expectNoCredentials(request, PASSWORD_A, TOKEN_A);
  });

  it("keeps active Share credentials during same-Share FileTree navigation", async () => {
    setActiveShare("share-A", PASSWORD_A, TOKEN_A);

    await fetchFromFileTree("share-A");

    const request = lastRequest();
    expect(request.url.searchParams.get("token")).toBe(TOKEN_A);
    expect(request.headers.get("X-SHARE-PASSWORD")).toBe(PASSWORD_A);
    expect(request.options.credentials).toBe("same-origin");
  });

  it("does not let a stale Share A callback re-read Share B credentials", async () => {
    const staleShareARequest = () => (
      resourcesApi.fetchFilesPublic("/stale", "share-A", PASSWORD_A)
    );
    setActiveShare("share-B", PASSWORD_B, TOKEN_B);

    await staleShareARequest();

    const request = lastRequest();
    expect(request.url.searchParams.get("hash")).toBe("share-A");
    expectNoCredentials(request, PASSWORD_A, TOKEN_A, PASSWORD_B, TOKEN_B);
  });

  it("snapshots each Share credential set before overlapping requests settle", async () => {
    const firstResponse = deferred();
    mocks.fetch
      .mockReturnValueOnce(firstResponse.promise)
      .mockResolvedValueOnce(successfulResponse());
    setActiveShare("share-A", PASSWORD_A, TOKEN_A);

    const requestA = resourcesApi.fetchFilesPublic("/a", "share-A", PASSWORD_A);
    setActiveShare("share-B", PASSWORD_B, TOKEN_B);
    await resourcesApi.fetchFilesPublic("/b", "share-B", PASSWORD_A);

    const [requestAURL, requestAOptions] = mocks.fetch.mock.calls[0];
    const [requestBURL, requestBOptions] = mocks.fetch.mock.calls[1];
    expect(new URL(requestAURL, "https://example.test").searchParams.get("token")).toBe(TOKEN_A);
    expect(new Headers(requestAOptions.headers).get("X-SHARE-PASSWORD")).toBe(PASSWORD_A);
    expect(new URL(requestBURL, "https://example.test").searchParams.get("token")).toBe(TOKEN_B);
    expect(new Headers(requestBOptions.headers).get("X-SHARE-PASSWORD")).toBe(PASSWORD_B);
    expect(JSON.stringify(mocks.fetch.mock.calls[1])).not.toContain(PASSWORD_A);
    expect(JSON.stringify(mocks.fetch.mock.calls[1])).not.toContain(TOKEN_A);

    firstResponse.resolve(successfulResponse());
    await requestA;
  });

  it("binds putPublic password, token, and Cookie mode to its hash", async () => {
    setActiveShare("share-A", PASSWORD_A, TOKEN_A);

    await resourcesApi.putPublic("share-B", "/file.txt", "content");
    expectNoCredentials(lastRequest(), PASSWORD_A, TOKEN_A);

    await resourcesApi.putPublic("share-A", "/file.txt", "content");
    const matchingRequest = lastRequest();
    expect(matchingRequest.url.searchParams.get("token")).toBe(TOKEN_A);
    expect(matchingRequest.headers.get("X-SHARE-PASSWORD")).toBe(PASSWORD_A);
    expect(matchingRequest.options.credentials).toBe("same-origin");
  });

  it("fails closed before postPublic can send mismatched caller Headers", () => {
    setActiveShare("share-A", PASSWORD_A, TOKEN_A);

    expect(() => resourcesApi.postPublic(
      "share-B",
      "/upload.txt",
      "content",
      false,
      undefined,
      {
        Authorization: "Bearer TOKEN-A",
        Cookie: "share=TOKEN-A",
        "X-SHARE-PASSWORD": PASSWORD_A,
      },
    )).toThrow("share is not active");
    expect(mocks.xmlHttpRequest).not.toHaveBeenCalled();
  });

  it("fails closed before a pause request can send mismatched session credentials", async () => {
    setActiveShare("share-A", PASSWORD_A, TOKEN_A);

    await expect(resourcesApi.signalUploadPause(null, "/upload.txt", "share-B"))
      .rejects.toThrow("share is not active");
    expect(mocks.fetchURL).not.toHaveBeenCalled();

    await resourcesApi.signalUploadPause(null, "/upload.txt", "share-A");
    expect(mocks.fetchURL).toHaveBeenCalledWith(
      expect.stringContaining("hash=share-A"),
      {
        headers: { "X-SHARE-PASSWORD": PASSWORD_A },
        method: "POST",
      },
    );
  });

  it("binds direct download token use to an exact non-empty Share hash", async () => {
    const file = { isDir: false, path: "/file.txt", source: "source-A" };
    setActiveShare("share-A", PASSWORD_A, TOKEN_A);

    await expect(resourcesApi.download(null, [file], "share-B"))
      .rejects.toThrow("share is not active");
    expect(mocks.getApiPath).not.toHaveBeenCalled();

    await resourcesApi.download(null, [file], "share-A");
    expect(mocks.getApiPath.mock.calls.at(-1)[1]).toMatchObject({
      hash: "share-A",
      token: TOKEN_A,
    });

    await resourcesApi.download(null, [file], "");
    const normalParams = mocks.getApiPath.mock.calls.at(-1)[1];
    expect(normalParams.source).toBe("source-A");
    expect(normalParams).not.toHaveProperty("token");
  });
});
