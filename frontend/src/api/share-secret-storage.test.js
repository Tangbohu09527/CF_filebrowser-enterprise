import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const runtimeFiles = [
  "src/views/Files.vue",
  "src/api/resources.js",
  "src/views/files/Preview.vue",
  "src/components/files/FileTree.vue",
];

describe("Share secret storage", () => {
  it.each(runtimeFiles)("does not persist Share passwords in %s", (file) => {
    const source = readFileSync(resolve(process.cwd(), file), "utf8");

    expect(source).not.toMatch(/localStorage\.(?:getItem|setItem)\(`sharepass:/);
  });
});
