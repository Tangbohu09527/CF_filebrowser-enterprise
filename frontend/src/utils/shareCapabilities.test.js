import { describe, expect, it } from "vitest";

import {
  SHARE_CAPABILITY_KEYS,
  deriveConfiguredShareCapabilities,
} from "./shareCapabilities.js";

const ALL_FALSE = Object.fromEntries(SHARE_CAPABILITY_KEYS.map((key) => [key, false]));
const ALL_TRUE = Object.fromEntries(SHARE_CAPABILITY_KEYS.map((key) => [key, true]));

function expectNineExplicitBooleans(capabilities) {
  expect(Object.keys(capabilities).sort()).toEqual([...SHARE_CAPABILITY_KEYS].sort());
  for (const key of SHARE_CAPABILITY_KEYS) {
    expect(Object.hasOwn(capabilities, key)).toBe(true);
    expect(typeof capabilities[key]).toBe("boolean");
  }
}

describe("configured Share capability derivation", () => {
  it.each([
    [{ thumbnail: false, viewer: false }, false],
    [{ thumbnail: true, viewer: false }, true],
    [{ thumbnail: false, viewer: true }, true],
    [{ thumbnail: true, viewer: true }, true],
  ])("derives normal Share preview from thumbnail/viewer", (configured, preview) => {
    const capabilities = deriveConfiguredShareCapabilities(
      { ...ALL_FALSE, browse: false, preview: !preview, ...configured },
      "normal",
    );

    expectNineExplicitBooleans(capabilities);
    expect(capabilities.browse).toBe(true);
    expect(capabilities.preview).toBe(preview);
  });

  it("forces upload Browse/Preview off and Create on without changing configurable capabilities", () => {
    const capabilities = deriveConfiguredShareCapabilities(
      {
        ...ALL_TRUE,
        create: false,
        modify: false,
        delete: false,
        replace: false,
      },
      "upload",
    );

    expectNineExplicitBooleans(capabilities);
    expect(capabilities).toStrictEqual({
      browse: false,
      preview: false,
      download: true,
      thumbnail: true,
      viewer: true,
      create: true,
      modify: false,
      delete: false,
      replace: false,
    });
  });
});
