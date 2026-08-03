import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("@/api", () => ({ resourcesApi: {}, usersApi: {} }));
vi.mock("@/i18n", () => ({ detectLocale: () => "en" }));
vi.mock("@/notify", () => ({ notify: {} }));
vi.mock("@/utils", () => ({ url: {} }));
vi.mock("@/utils/mimetype", () => ({ getTypeInfo: vi.fn() }));
vi.mock("@/utils/sort.js", () => ({ sortedItems: vi.fn() }));
vi.mock("./eventBus", () => ({ emitStateChanged: vi.fn() }));
vi.mock("./getters.js", () => ({ getters: {} }));

import { mutations } from "./mutations.js";
import { state } from "./state.js";

const initialShareInfo = { ...state.shareInfo };

afterEach(() => {
  state.sharePassword = "";
  state.shareInfo = { ...initialShareInfo };
});

describe("Share password store lifecycle", () => {
  it("clearShareData clears Share metadata and the in-memory password together", () => {
    state.sharePassword = "runtime-share-secret";
    state.shareInfo = {
      ...initialShareInfo,
      hash: "share-a",
      token: "runtime-token",
      passwordValid: true,
    };

    mutations.clearShareData();

    expect(state.sharePassword).toBe("");
    expect(state.shareInfo).toMatchObject({
      hash: "",
      token: "",
      passwordValid: false,
      isShare: false,
    });
  });
});
