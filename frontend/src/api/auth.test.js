import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  fetchJSON: vi.fn(),
  fetchURL: vi.fn(),
  getApiPath: vi.fn(() => "/api/auth/token"),
  showError: vi.fn(),
}));

vi.mock("@/api/utils", () => ({
  fetchJSON: mocks.fetchJSON,
  fetchURL: mocks.fetchURL,
}));

vi.mock("@/notify", () => ({
  notify: {
    showError: mocks.showError,
  },
}));

vi.mock("@/utils/url.js", () => ({
  getApiPath: mocks.getApiPath,
}));

import { createApiKey, deleteApiKey } from "./auth.js";

describe("API token requests", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("returns the one-time token creation response", async () => {
    const response = { message: "created", token: "one-time-secret" };
    mocks.fetchJSON.mockResolvedValue(response);

    await expect(createApiKey({ name: "ci", days: 1 })).resolves.toBe(response);
    expect(mocks.fetchJSON).toHaveBeenCalledWith("/api/auth/token", {
      method: "POST",
    });
  });

  it("keeps the delete request pending until the API completes", async () => {
    let resolveRequest;
    mocks.fetchURL.mockReturnValue(new Promise((resolve) => {
      resolveRequest = resolve;
    }));

    let completed = false;
    const deletion = deleteApiKey({ name: "ci" }).then(() => {
      completed = true;
    });

    await Promise.resolve();
    expect(completed).toBe(false);

    resolveRequest();
    await deletion;
    expect(completed).toBe(true);
  });
});
