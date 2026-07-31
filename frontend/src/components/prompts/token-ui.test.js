import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  closeTopPrompt: vi.fn(),
  showPrompt: vi.fn(),
  createApiKey: vi.fn(),
  deleteApiKey: vi.fn(),
  getApiKeys: vi.fn(),
  emit: vi.fn(),
  on: vi.fn(),
  off: vi.fn(),
  showError: vi.fn(),
  showSuccessToast: vi.fn(),
}));

vi.mock("@/api", () => ({
  authApi: {
    createApiKey: mocks.createApiKey,
    deleteApiKey: mocks.deleteApiKey,
    getApiKeys: mocks.getApiKeys,
  },
}));

vi.mock("@/store", () => ({
  state: {
    activeSettingsView: "api",
    settings: {},
    user: {
      permissions: { api: true, browse: true },
    },
  },
  mutations: {
    closeTopPrompt: mocks.closeTopPrompt,
    showPrompt: mocks.showPrompt,
  },
}));

vi.mock("@/notify", () => ({
  notify: {
    showError: mocks.showError,
    showSuccessToast: mocks.showSuccessToast,
  },
}));

vi.mock("@/store/eventBus", () => ({
  eventBus: {
    emit: mocks.emit,
    on: mocks.on,
    off: mocks.off,
  },
}));

import CreateApi from "./CreateApi.vue";
import ActionApi from "./ActionApi.vue";
import Api from "@/views/settings/Api.vue";

const translate = (key) => key;
const originalClipboard = Object.getOwnPropertyDescriptor(navigator, "clipboard");
const originalExecCommand = Object.getOwnPropertyDescriptor(document, "execCommand");
const secret = "one-time-secret";

function setClipboard(writeText) {
  Object.defineProperty(navigator, "clipboard", {
    configurable: true,
    value: { writeText },
  });
}

function setExecCommand(execCommand) {
  Object.defineProperty(document, "execCommand", {
    configurable: true,
    value: execCommand,
  });
}

function captureNotificationHistory() {
  const notificationHistory = [];
  mocks.showError.mockImplementation((message) => {
    notificationHistory.push({ message });
    sessionStorage.setItem(
      "notificationHistory",
      JSON.stringify(notificationHistory),
    );
  });
  return notificationHistory;
}

function expectSecretNotPersisted(notificationHistory = []) {
  const notifyCalls = [
    ...mocks.showError.mock.calls,
    ...mocks.showSuccessToast.mock.calls,
  ];
  expect(JSON.stringify(notifyCalls)).not.toContain(secret);
  expect(JSON.stringify(notificationHistory)).not.toContain(secret);
  expect(sessionStorage.getItem("notificationHistory") ?? "").not.toContain(secret);
}

afterEach(() => {
  document.body.innerHTML = "";
  sessionStorage.clear();

  if (originalClipboard) {
    Object.defineProperty(navigator, "clipboard", originalClipboard);
  } else {
    delete navigator.clipboard;
  }

  if (originalExecCommand) {
    Object.defineProperty(document, "execCommand", originalExecCommand);
  } else {
    delete document.execCommand;
  }

  vi.restoreAllMocks();
});

describe("API token creation", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.showError.mockReset();
    mocks.showSuccessToast.mockReset();
  });

  it("keeps the one-time secret only in the creation component", async () => {
    mocks.createApiKey.mockResolvedValue({ token: "one-time-secret" });
    const context = {
      ...CreateApi.data(),
      apiName: "ci",
      durationInDays: 1,
      $t: translate,
    };

    await CreateApi.methods.createAPIKey.call(context);

    expect(context.createdToken).toBe("one-time-secret");
    expect(mocks.showPrompt).not.toHaveBeenCalled();
    expect(mocks.closeTopPrompt).not.toHaveBeenCalled();
    expect(mocks.emit).toHaveBeenCalledWith("apiKeysChanged");
  });

  it("copies the locally held secret with the Clipboard API", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    const execCommand = vi.fn();
    setClipboard(writeText);
    setExecCommand(execCommand);
    const context = { createdToken: secret, $t: translate };

    await CreateApi.methods.copyCreatedToken.call(context);

    expect(writeText).toHaveBeenCalledWith(secret);
    expect(execCommand).not.toHaveBeenCalled();
    expect(document.querySelector("textarea")).toBeNull();
    expect(mocks.showSuccessToast).toHaveBeenCalledWith("buttons.copySuccess");
    expect(mocks.showError).not.toHaveBeenCalled();
    expectSecretNotPersisted();
  });

  it("falls back to execCommand and removes the textarea after success", async () => {
    const writeText = vi.fn().mockRejectedValue(new Error("clipboard unavailable"));
    const execCommand = vi.fn().mockReturnValue(true);
    setClipboard(writeText);
    setExecCommand(execCommand);
    const context = { createdToken: secret, $t: translate };

    await CreateApi.methods.copyCreatedToken.call(context);

    expect(writeText).toHaveBeenCalledWith(secret);
    expect(execCommand).toHaveBeenCalledWith("copy");
    expect(document.querySelector("textarea")).toBeNull();
    expect(mocks.showSuccessToast).toHaveBeenCalledWith("buttons.copySuccess");
    expect(mocks.showError).not.toHaveBeenCalled();
    expectSecretNotPersisted();
  });

  it("uses a fixed failure notification when execCommand returns false", async () => {
    const notificationHistory = captureNotificationHistory();
    setClipboard(vi.fn().mockRejectedValue(new Error("clipboard unavailable")));
    setExecCommand(vi.fn().mockReturnValue(false));
    const context = { createdToken: secret, $t: translate };

    await CreateApi.methods.copyCreatedToken.call(context);

    expect(document.querySelector("textarea")).toBeNull();
    expect(mocks.showSuccessToast).not.toHaveBeenCalled();
    expect(mocks.showError).toHaveBeenCalledWith("buttons.copyFailed");
    expectSecretNotPersisted(notificationHistory);
  });

  it("removes the textarea and does not expose the secret when execCommand throws", async () => {
    const notificationHistory = captureNotificationHistory();
    const consoleError = vi.spyOn(console, "error").mockImplementation(() => {});
    setClipboard(vi.fn().mockRejectedValue(new Error("clipboard unavailable")));
    setExecCommand(vi.fn(() => {
      throw new Error("copy unavailable");
    }));
    const context = { createdToken: secret, $t: translate };

    await CreateApi.methods.copyCreatedToken.call(context);

    expect(document.querySelector("textarea")).toBeNull();
    expect(mocks.showSuccessToast).not.toHaveBeenCalled();
    expect(mocks.showError).toHaveBeenCalledWith("buttons.copyFailed");
    expect(consoleError).not.toHaveBeenCalled();
    expectSecretNotPersisted(notificationHistory);
  });
});

describe("API token deletion", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("waits for deletion before refreshing and closing", async () => {
    let resolveRequest;
    mocks.deleteApiKey.mockReturnValue(new Promise((resolve) => {
      resolveRequest = resolve;
    }));
    const context = { name: "ci", deleting: false, $t: translate };

    const deletion = ActionApi.methods.deleteApi.call(context);

    expect(context.deleting).toBe(true);
    expect(mocks.emit).not.toHaveBeenCalled();
    expect(mocks.closeTopPrompt).not.toHaveBeenCalled();

    resolveRequest();
    await deletion;

    expect(mocks.emit).toHaveBeenCalledWith("apiKeysChanged");
    expect(mocks.closeTopPrompt).toHaveBeenCalledOnce();
    expect(context.deleting).toBe(false);
  });

  it("keeps the prompt open when deletion fails", async () => {
    const rejection = Promise.reject(new Error("delete failed"));
    rejection.catch(() => {});
    mocks.deleteApiKey.mockReturnValue(rejection);
    const context = { name: "ci", deleting: false, $t: translate };

    await ActionApi.methods.deleteApi.call(context);

    expect(mocks.emit).not.toHaveBeenCalled();
    expect(mocks.closeTopPrompt).not.toHaveBeenCalled();
    expect(context.deleting).toBe(false);
  });

  it("ignores repeated deletion while one is in progress", async () => {
    const context = { name: "ci", deleting: true, $t: translate };

    await ActionApi.methods.deleteApi.call(context);

    expect(mocks.deleteApiKey).not.toHaveBeenCalled();
  });
});

describe("API token list", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("contains only redacted token metadata columns and actions", () => {
    const columns = Api.computed.apiTableColumns.call({ $t: translate });

    expect(columns.map(({ key }) => key)).toEqual([
      "name",
      "type",
      "tokenPrefix",
      "issuedAt",
      "expiresAt",
      "capabilities",
      "actions",
    ]);
  });

  it("clears stale rows when the refreshed list is empty", async () => {
    mocks.getApiKeys.mockRejectedValue({ status: 404 });
    const context = {
      error: new Error("stale"),
      links: [{ name: "deleted" }],
      loading: false,
    };

    await Api.methods.reloadApiKeys.call(context);

    expect(context.links).toEqual([]);
    expect(context.error).toBeNull();
    expect(context.loading).toBe(false);
  });

  it("shows only enabled capabilities", () => {
    const result = Api.methods.capabilityNames({
      Permissions: { api: true, browse: true, delete: false },
    });

    expect(result).toBe("api, browse");
  });
});
