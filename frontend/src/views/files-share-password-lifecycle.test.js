import { createApp } from "vue";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => {
  const state = {
    deletedItem: false,
    loading: {},
    navigation: { isTransitioning: false },
    notificationHistory: [],
    previousHistoryItem: { name: "", path: "", source: "" },
    prompts: [],
    promptIdCounter: 0,
    reload: false,
    req: { items: [], path: "/", source: "default", type: "directory" },
    route: { path: "/public/share/share-a/" },
    selected: [],
    shareInfo: { hash: "", subPath: "", shareType: "" },
    sharePassword: "",
    sources: { count: 1, current: "default" },
    user: { sorting: { by: "name", asc: true } },
  };
  const route = { hash: "share-a", path: "/share-a/" };

  const clearShareData = vi.fn(() => {
    state.sharePassword = "";
    state.shareInfo = { hash: "", subPath: "", shareType: "" };
  });
  const closeTopPrompt = vi.fn((id) => {
    const index = state.prompts.findIndex((prompt) => prompt.id === id);
    if (index !== -1) {
      state.prompts.splice(index, 1);
    }
  });
  const setSharePassword = vi.fn((password) => {
    state.sharePassword = password;
  });
  const setShareInfo = vi.fn((shareInfo) => {
    state.shareInfo = shareInfo;
  });
  const setShareData = vi.fn((data) => {
    state.shareInfo = { ...state.shareInfo, ...data };
  });
  const setLoading = vi.fn((loadType, status) => {
    if (status === false) {
      delete state.loading[loadType];
    } else {
      state.loading[loadType] = true;
    }
  });
  const showPrompt = vi.fn((prompt) => {
    state.promptIdCounter += 1;
    state.prompts.push({ id: state.promptIdCounter, ...prompt });
  });

  return {
    state,
    route,
    clearShareData,
    closeTopPrompt,
    setSharePassword,
    setShareInfo,
    setShareData,
    setLoading,
    showPrompt,
    fetchFilesPublic: vi.fn(),
    getShareInfoPublic: vi.fn(),
    replaceRequest: vi.fn(),
    routerPush: vi.fn(),
    showError: vi.fn(),
  };
});

vi.mock("@/api", () => ({
  mediaApi: { fetchDirectoryMediaMetadataPublic: vi.fn() },
  resourcesApi: { fetchFilesPublic: mocks.fetchFilesPublic },
  shareApi: { getShareInfoPublic: mocks.getShareInfoPublic },
}));

vi.mock("@/store", () => ({
  state: mocks.state,
  getters: {
    eventTheme: vi.fn(() => ""),
    fileViewingDisabled: vi.fn(() => false),
    isLoggedIn: vi.fn(() => true),
    routePath: vi.fn(() => mocks.route.path),
    shareHash: vi.fn(() => mocks.route.hash),
  },
  mutations: {
    clearShareData: mocks.clearShareData,
    closeTopPrompt: mocks.closeTopPrompt,
    replaceRequest: mocks.replaceRequest,
    resetSelected: vi.fn(),
    setLoading: mocks.setLoading,
    setMultiple: vi.fn(),
    setNavigationTransitioning: vi.fn(),
    setReload: vi.fn(),
    setShareData: mocks.setShareData,
    setShareInfo: mocks.setShareInfo,
    setSharePassword: mocks.setSharePassword,
    setSidebarVisible: vi.fn(),
    showPrompt: mocks.showPrompt,
    updateListingSortConfig: vi.fn(),
  },
}));

vi.mock("@/router", () => ({ default: { push: mocks.routerPush } }));
vi.mock("@/utils", () => ({ url: { removeLastDir: vi.fn(() => "/") } }));
vi.mock("@/utils/url", () => ({ extractSourceFromPath: vi.fn(() => ({ path: "/", source: "default" })) }));
vi.mock("@/utils/constants", () => ({ globalVars: { name: "FileBrowser" } }));
vi.mock("@/views/Errors.vue", () => ({ default: {} }));
vi.mock("@/components/LoadingSpinner.vue", () => ({ default: {} }));
vi.mock("./files/Preview.vue", () => ({ default: {} }));
vi.mock("./files/ListingView.vue", () => ({ default: {} }));
vi.mock("./files/Editor.vue", () => ({ default: {} }));
vi.mock("./files/OnlyOfficeEditor.vue", () => ({ default: {} }));
vi.mock("./files/EpubViewer.vue", () => ({ default: {} }));
vi.mock("./files/DocViewer.vue", () => ({ default: {} }));
vi.mock("./files/MarkdownViewer.vue", () => ({ default: {} }));
vi.mock("./files/ThreeJs.vue", () => ({ default: {} }));

import Files from "./Files.vue";
import Password from "@/components/prompts/Password.vue";

const secret = "share-lifecycle-secret";
let consoleError;
let consoleLog;
let consoleWarn;
let storageSetItem;

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, reject, resolve };
}

async function flushPromises() {
  for (let index = 0; index < 5; index += 1) {
    await Promise.resolve();
  }
}

function filesContext(overrides = {}) {
  const context = {
    ...Files.data(),
    $t: (key) => key,
    ...overrides,
  };
  for (const [name, method] of Object.entries(Files.methods)) {
    context[name] = method.bind(context);
  }
  return context;
}

function validUploadShare(overrides = {}) {
  return {
    hasPassword: true,
    shareType: "upload",
    status: 200,
    ...overrides,
  };
}

function expectSecretAbsent() {
  const storageValues = (storage) =>
    Array.from({ length: storage.length }, (_, index) => storage.getItem(storage.key(index)));
  const formValues = [...document.querySelectorAll("input, textarea")].map((element) => element.value);

  expect(mocks.state.sharePassword).not.toContain(secret);
  expect(JSON.stringify(mocks.state.prompts)).not.toContain(secret);
  expect(JSON.stringify(mocks.showPrompt.mock.calls)).not.toContain(secret);
  expect(JSON.stringify(mocks.state.notificationHistory)).not.toContain(secret);
  expect(JSON.stringify(storageValues(localStorage))).not.toContain(secret);
  expect(JSON.stringify(storageValues(sessionStorage))).not.toContain(secret);
  expect(document.body.textContent).not.toContain(secret);
  expect(JSON.stringify(formValues)).not.toContain(secret);
  expect(window.location.href).not.toContain(secret);
  expect(JSON.stringify(storageSetItem.mock.calls)).not.toContain(secret);
  expect(JSON.stringify(mocks.showError.mock.calls)).not.toContain(secret);
  expect(JSON.stringify(consoleError.mock.calls)).not.toContain(secret);
  expect(JSON.stringify(consoleWarn.mock.calls)).not.toContain(secret);
  expect(JSON.stringify(consoleLog.mock.calls)).not.toContain(secret);
}

beforeEach(() => {
  vi.clearAllMocks();
  localStorage.clear();
  sessionStorage.clear();
  document.body.innerHTML = "";
  mocks.route.hash = "share-a";
  mocks.route.path = "/share-a/";
  mocks.state.deletedItem = false;
  mocks.state.loading = {};
  mocks.state.navigation.isTransitioning = false;
  mocks.state.notificationHistory = [];
  mocks.state.prompts = [];
  mocks.state.promptIdCounter = 0;
  mocks.state.route.path = "/public/share/share-a/";
  mocks.state.shareInfo = { hash: "", subPath: "", shareType: "" };
  mocks.state.sharePassword = "";
  mocks.getShareInfoPublic.mockResolvedValue(validUploadShare());
  mocks.fetchFilesPublic.mockRejectedValue({ status: 501 });
  consoleError = vi.spyOn(console, "error").mockImplementation(() => {});
  consoleWarn = vi.spyOn(console, "warn").mockImplementation(() => {});
  consoleLog = vi.spyOn(console, "log").mockImplementation(() => {});
  storageSetItem = vi.spyOn(Storage.prototype, "setItem");
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("Public Share password lifecycle", () => {
  it("clears the local/store password and its prompt copy when Files unmounts", () => {
    mocks.state.shareInfo = { hash: "share-a", subPath: "/", shareType: "normal" };
    mocks.state.sharePassword = secret;
    mocks.state.prompts = [{ id: 7, name: "password", props: { initialPassword: secret } }];
    const context = filesContext({
      attemptedPasswordLogin: true,
      sharePassword: secret,
      sharePasswordPromptId: 7,
    });

    Files.beforeUnmount.call(context);

    expect(context.sharePassword).toBe("");
    expect(context.attemptedPasswordLogin).toBe(false);
    expect(mocks.state.shareInfo.hash).toBe("");
    expectSecretAbsent();
  });

  it("clears Share A before loading Share B and keeps it cleared when B fails", async () => {
    mocks.route.hash = "share-b";
    mocks.route.path = "/share-b/";
    mocks.state.shareInfo = { hash: "share-a", subPath: "/", shareType: "normal" };
    mocks.state.sharePassword = secret;
    mocks.getShareInfoPublic.mockRejectedValue(new Error("share metadata unavailable"));
    const context = filesContext({ sharePassword: secret });

    await expect(context.fetchData()).rejects.toThrow("share metadata unavailable");

    expect(context.sharePassword).toBe("");
    expect(mocks.state.shareInfo.hash).toBe("");
    expectSecretAbsent();
  });

  it("clears the password when leaving the Public Share route", async () => {
    mocks.route.hash = "";
    mocks.route.path = "/files/default/";
    mocks.state.deletedItem = true;
    mocks.state.shareInfo = { hash: "share-a", subPath: "/", shareType: "normal" };
    mocks.state.sharePassword = secret;
    const context = filesContext({ sharePassword: secret });

    await context.fetchData();

    expect(context.sharePassword).toBe("");
    expect(mocks.state.shareInfo.hash).toBe("");
    expectSecretAbsent();
  });

  it("clears an old password when the current Share metadata load fails", async () => {
    mocks.state.shareInfo = { hash: "share-a", subPath: "/", shareType: "normal" };
    mocks.state.sharePassword = secret;
    mocks.getShareInfoPublic.mockRejectedValue(new Error("share metadata unavailable"));
    const context = filesContext();

    await expect(context.fetchData()).rejects.toThrow("share metadata unavailable");

    expect(context.sharePassword).toBe("");
    expectSecretAbsent();
  });

  it("clears an old password when the current Share response is invalid", async () => {
    mocks.state.shareInfo = { hash: "share-a", subPath: "/", shareType: "normal" };
    mocks.state.sharePassword = secret;
    mocks.getShareInfoPublic.mockResolvedValue({ status: 404, message: "gone" });
    const context = filesContext();

    await context.fetchData();

    expect(context.error).toMatchObject({ status: 404, message: "gone" });
    expect(context.sharePassword).toBe("");
    expectSecretAbsent();
  });

  it("retains the password during directory navigation within the same Share hash", async () => {
    mocks.state.shareInfo = { hash: "share-a", subPath: "/old", shareType: "upload" };
    mocks.state.sharePassword = secret;
    mocks.route.path = "/share-a/new-directory";
    const context = filesContext();

    await context.fetchData();

    expect(context.sharePassword).toBe(secret);
    expect(mocks.state.sharePassword).toBe(secret);
    expect(mocks.state.shareInfo.hash).toBe("share-a");
  });

  it("ignores an older same-hash metadata failure after newer navigation succeeds", async () => {
    const older = deferred();
    const newer = deferred();
    mocks.state.shareInfo = { hash: "share-a", subPath: "/old", shareType: "upload" };
    mocks.state.sharePassword = secret;
    mocks.getShareInfoPublic
      .mockImplementationOnce(() => older.promise)
      .mockImplementationOnce(() => newer.promise);
    const context = filesContext();

    const olderFetch = context.fetchData();
    mocks.route.path = "/share-a/new-directory";
    const newerFetch = context.fetchData();
    newer.resolve(validUploadShare());
    await newerFetch;
    older.reject(new Error("stale metadata failure"));

    await expect(olderFetch).resolves.toBeUndefined();
    expect(context.sharePassword).toBe(secret);
    expect(mocks.state.sharePassword).toBe(secret);
    expect(mocks.state.shareInfo.hash).toBe("share-a");
  });

  it("ignores a pending metadata response after component unmount", async () => {
    const pending = deferred();
    mocks.state.shareInfo = { hash: "share-a", subPath: "/", shareType: "normal" };
    mocks.state.sharePassword = secret;
    mocks.getShareInfoPublic.mockImplementationOnce(() => pending.promise);
    const context = filesContext();

    const fetch = context.fetchData();
    Files.beforeUnmount.call(context);
    pending.resolve(validUploadShare());
    await fetch;

    expect(mocks.state.shareInfo.hash).toBe("");
    expect(mocks.state.prompts).toEqual([]);
    expectSecretAbsent();
  });

  it("does not combine Share A's password with Share B state after a resource response", async () => {
    const shareAResource = deferred();
    const shareBMetadata = deferred();
    mocks.state.shareInfo = { hash: "share-a", subPath: "/old", shareType: "normal" };
    mocks.state.sharePassword = secret;
    mocks.getShareInfoPublic
      .mockResolvedValueOnce(validUploadShare({ shareType: "normal" }))
      .mockImplementationOnce(() => shareBMetadata.promise);
    mocks.fetchFilesPublic
      .mockReset()
      .mockResolvedValueOnce({})
      .mockImplementationOnce(() => shareAResource.promise)
      .mockResolvedValue({ name: "late-a", token: "late-a-token", type: "text/plain" });
    const context = filesContext();

    const shareAFetch = context.fetchData();
    await flushPromises();
    expect(mocks.fetchFilesPublic).toHaveBeenCalledTimes(2);

    mocks.route.hash = "share-b";
    mocks.route.path = "/share-b/";
    const shareBFetch = context.fetchData();
    shareAResource.resolve({ name: "a.txt", token: "share-a-token", type: "text/plain" });
    await shareAFetch;

    const crossShareCalls = mocks.fetchFilesPublic.mock.calls.slice(2).filter((call) => {
      const [, hash, password] = call;
      return password === secret && hash !== "share-a";
    });
    expect(crossShareCalls).toEqual([]);
    expect(mocks.state.shareInfo.token).toBeUndefined();

    shareBMetadata.resolve({ status: 404 });
    await shareBFetch;
    expect(mocks.state.loading).toEqual({});
  });

  it("does not issue follow-up resource requests after component unmount", async () => {
    const shareResource = deferred();
    mocks.state.shareInfo = { hash: "share-a", subPath: "/", shareType: "normal" };
    mocks.state.sharePassword = secret;
    mocks.getShareInfoPublic.mockResolvedValueOnce(validUploadShare({ shareType: "normal" }));
    mocks.fetchFilesPublic
      .mockReset()
      .mockResolvedValueOnce({})
      .mockImplementationOnce(() => shareResource.promise)
      .mockResolvedValue({ name: "late-a", token: "late-a-token", type: "text/plain" });
    const context = filesContext();

    const fetch = context.fetchData();
    await flushPromises();
    expect(mocks.fetchFilesPublic).toHaveBeenCalledTimes(2);
    Files.beforeUnmount.call(context);
    shareResource.resolve({ name: "a.txt", token: "share-a-token", type: "text/plain" });
    await fetch;

    const followUpCalls = mocks.fetchFilesPublic.mock.calls.slice(2);
    expect(followUpCalls).toEqual([]);
    expect(mocks.state.shareInfo.token).toBeUndefined();
    expect(mocks.state.loading).toEqual({});
    expectSecretAbsent();
  });

  it("removes a password prompt secret when the Public Share session is cleared", () => {
    mocks.state.shareInfo = { hash: "share-a", subPath: "/", shareType: "normal" };
    mocks.state.sharePassword = secret;
    const context = filesContext({ sharePassword: secret });

    context.showPasswordPrompt();
    expect(JSON.stringify(mocks.state.prompts)).not.toContain(secret);
    const prompt = mocks.state.prompts.at(-1);
    const root = document.createElement("div");
    document.body.appendChild(root);
    const app = createApp(Password, prompt.props);
    app.config.globalProperties.$t = (key) => key;
    app.directive("focus", {});
    app.mount(root);
    expect(root.querySelector('input[type="password"]').value).toBe("");
    app.unmount();
    root.remove();

    context.clearShareSession();

    expect(context.sharePasswordPromptId).toBeNull();
    expectSecretAbsent();
  });
});
