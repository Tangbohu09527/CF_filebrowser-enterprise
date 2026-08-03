import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  showError: vi.fn(),
  showSuccess: vi.fn(),
  showSuccessToast: vi.fn(),
}));

vi.mock("@/i18n", () => ({
  default: { global: { t: (key) => key } },
}));

vi.mock("@/notify", () => ({
  notify: {
    showError: mocks.showError,
    showSuccess: mocks.showSuccess,
    showSuccessToast: mocks.showSuccessToast,
  },
}));

import { copyToClipboard } from "./clipboard.js";

const originalClipboard = Object.getOwnPropertyDescriptor(navigator, "clipboard");
const originalExecCommand = Object.getOwnPropertyDescriptor(document, "execCommand");
const secret = "share-password-must-not-leak";

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

function restoreProperty(target, name, descriptor) {
  if (descriptor) {
    Object.defineProperty(target, name, descriptor);
  } else {
    delete target[name];
  }
}

beforeEach(() => {
  vi.clearAllMocks();
  localStorage.clear();
  sessionStorage.clear();
});

afterEach(() => {
  document.body.innerHTML = "";
  restoreProperty(navigator, "clipboard", originalClipboard);
  restoreProperty(document, "execCommand", originalExecCommand);
  vi.restoreAllMocks();
});

describe("clipboard failure handling", () => {
  it("does not expose copied Share text through notifications, logs, DOM, or Web Storage", async () => {
    setClipboard(vi.fn().mockRejectedValue(new Error("clipboard unavailable")));
    setExecCommand(vi.fn(() => {
      throw new Error("copy unavailable");
    }));
    const consoleError = vi.spyOn(console, "error").mockImplementation(() => {});
    const consoleWarn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const consoleLog = vi.spyOn(console, "log").mockImplementation(() => {});

    await expect(copyToClipboard(secret)).resolves.toBe(false);

    const notificationCalls = [
      ...mocks.showError.mock.calls,
      ...mocks.showSuccess.mock.calls,
      ...mocks.showSuccessToast.mock.calls,
    ];
    expect(JSON.stringify(notificationCalls)).not.toContain(secret);
    expect(consoleError).not.toHaveBeenCalled();
    expect(consoleWarn).not.toHaveBeenCalled();
    expect(consoleLog).not.toHaveBeenCalled();
    expect(document.querySelector("textarea")).toBeNull();
    expect(JSON.stringify({ ...localStorage })).not.toContain(secret);
    expect(JSON.stringify({ ...sessionStorage })).not.toContain(secret);
  });
});
