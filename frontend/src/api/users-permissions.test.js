import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  fetchURL: vi.fn(),
  showPrompt: vi.fn(),
}));

vi.mock("@/api/utils", () => ({
  fetchJSON: vi.fn(),
  fetchURL: mocks.fetchURL,
}));

vi.mock("@/utils/url.js", () => ({
  getApiPath: vi.fn(() => "/api/users"),
  getPublicApiPath: vi.fn(),
}));

vi.mock("@/notify", () => ({
  notify: { showError: vi.fn() },
}));

vi.mock("@/store/state.js", () => ({
  state: { user: { loginMethod: "password" } },
}));

vi.mock("@/store/mutations.js", () => ({
  mutations: { showPrompt: mocks.showPrompt },
}));

vi.mock("@/i18n", () => ({
  default: { global: { t: (key) => key } },
}));

import * as usersApi from "./users.js";

const permissions = {
  browse: false,
  preview: true,
  download: false,
};

beforeEach(() => {
  vi.clearAllMocks();
});

describe("user permission request serialization", () => {
  it("keeps explicit false values in POST /api/users", async () => {
    mocks.fetchURL.mockResolvedValue({
      status: 201,
      headers: { get: vi.fn(() => "/api/users/42") },
    });

    await usersApi.create({ username: "reader", permissions });

    const request = mocks.fetchURL.mock.calls[0][1];
    expect(JSON.parse(request.body)).toEqual({
      which: [],
      data: { username: "reader", permissions },
    });
  });

  it("keeps explicit false values in PUT /api/users", async () => {
    mocks.fetchURL.mockResolvedValue({ status: 200 });

    await usersApi.update({ id: 42, username: "reader", permissions }, ["all"]);

    const request = mocks.fetchURL.mock.calls[0][1];
    expect(JSON.parse(request.body)).toEqual({
      which: ["all"],
      data: { id: 42, username: "reader", permissions },
    });
  });
});
