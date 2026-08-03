import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const runtimeFiles = [
  "src/views/Files.vue",
  "src/api/resources.js",
  "src/views/files/Preview.vue",
  "src/components/files/FileTree.vue",
  "src/components/prompts/Password.vue",
  "src/store/mutations.js",
  "src/store/state.js",
];

describe("Share secret storage", () => {
  it.each(runtimeFiles)("does not persist Share passwords in %s", (file) => {
    const source = readFileSync(resolve(process.cwd(), file), "utf8");

    expect(source).not.toContain("sharepass:");
    expect(source).not.toMatch(
      /(?:localStorage|sessionStorage)\.(?:getItem|setItem)[\s\S]{0,160}(?:sharePassword|sharepass:)/,
    );
  });
});
