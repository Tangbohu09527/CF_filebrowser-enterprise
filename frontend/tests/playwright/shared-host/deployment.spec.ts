import { createHash } from "node:crypto";
import { appendFile, mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { expect, test, type Page, type TestInfo } from "@playwright/test";

let credentials: { username: string; password: string };
let source: string;

const digest = (bytes: Buffer) => createHash("sha256").update(bytes).digest("hex");
const listing = () => `/files/${encodeURIComponent(source)}/`;
const item = (page: Page, name: string) => page.locator(`a[aria-label=${JSON.stringify(name)}]`);

test.beforeAll(async () => {
  const filename = process.env.FILEBROWSER_ACCEPTANCE_STATE;
  if (!filename) throw new Error("A protected acceptance state file is required");
  const metadata = await stat(filename);
  if ((metadata.mode & 0o077) !== 0) throw new Error("Acceptance state must not be group/world readable");
  const state = JSON.parse(await readFile(filename, "utf8"));
  credentials = state.ui;
  source = state.source;
  if (!credentials?.username || !credentials?.password || !source) {
    throw new Error("Acceptance state requires an ordinary UI user and source");
  }
});

const evidenceCaseIds: Record<string, string> = {
  "ordinary user uploads, edits, renames, downloads exact bytes and deletes": "crud",
  "decodes the actual picture.png preview": "png",
  "decodes the actual photo.jpg preview": "jpg",
  "renders distinct nonblank XLSX content in the actual document viewer": "xlsx",
  "ordinary user logs out and loses access to the listing": "logout",
};

type UIStage = "login" | "listing" | "upload" | "edit" | "save" | "rename" | "download" | "delete" |
  "png" | "jpg" | "xlsx" | "logout";
// A stage means only the last operation entered, never that it completed.
const enteredStage = new WeakMap<TestInfo, UIStage>();
const enterStage = (testInfo: TestInfo, stage: UIStage) => enteredStage.set(testInfo, stage);

test.afterEach(async ({}, testInfo) => {
  const caseId = evidenceCaseIds[testInfo.title];
  const status = testInfo.status;
  const output = process.env.FILEBROWSER_ACCEPTANCE_OUTPUT;
  if (!caseId || !status || !["passed", "failed", "timedOut", "skipped", "interrupted"].includes(status) ||
      !Number.isInteger(testInfo.retry) || testInfo.retry < 0 || testInfo.retry > 2 || !output) {
    throw new Error("UI case evidence metadata is invalid");
  }
  await mkdir(output, { recursive: true, mode: 0o700 });
  await appendFile(resolve(output, "ui-case-evidence.ndjson"),
    JSON.stringify({ case: caseId, status, retry: testInfo.retry, stage: enteredStage.get(testInfo) ?? null }) + "\n", { mode: 0o600 });
});

test.beforeEach(async ({ page }, testInfo) => {
  enterStage(testInfo, "login");
  await page.goto("/login");
  await page.getByPlaceholder("Username").fill(credentials.username);
  await page.getByPlaceholder("Password").fill(credentials.password);
  await page.getByRole("button", { name: "Login", exact: true }).click();
  await page.waitForURL("**/files/**");
  enterStage(testInfo, "listing");
  await page.goto(listing());
  await expect(page.locator(".listing-items")).toBeVisible();
});

test("ordinary user uploads, edits, renames, downloads exact bytes and deletes", async ({ page }, testInfo) => {
  const originalName = `ui-${Date.now()} 中文 空格.txt`;
  const renamedBase = `ui-${Date.now()} renamed`;
  const renamedName = renamedBase + ".txt";
  const original = Buffer.from("UI upload with Chinese filename.\n", "utf8");
  const edited = Buffer.from("Saved through the existing editor.\n", "utf8");

  enterStage(testInfo, "upload");
  await page.locator("#upload-input").setInputFiles({ name: originalName, mimeType: "text/plain", buffer: original });
  await expect(item(page, originalName)).toBeVisible({ timeout: 30000 });
  enterStage(testInfo, "edit");
  await item(page, originalName).dblclick();
  await expect(page.locator(".ace_text-layer")).toContainText("UI upload with Chinese filename.");
  await page.locator(".ace_content").click();
  await page.keyboard.press("ControlOrMeta+A");
  await page.keyboard.insertText(edited.toString("utf8"));
  enterStage(testInfo, "save");
  const saved = page.waitForResponse((response) =>
    response.url().includes("/api/resources") && ["PUT", "POST"].includes(response.request().method()));
  await page.locator(".overflow-menu-button").click();
  await page.locator('button[aria-label="Save"]').click();
  expect((await saved).ok()).toBeTruthy();
  await page.goto(listing());

  enterStage(testInfo, "rename");
  await item(page, originalName).click({ button: "right" });
  await page.locator('button[aria-label="Rename"]').click();
  await page.locator('input[aria-label="New Name"]').fill(renamedBase);
  await page.locator('button[aria-label="Submit"]').click();
  await expect(item(page, renamedName)).toBeVisible();
  await expect(item(page, originalName)).toHaveCount(0);

  enterStage(testInfo, "download");
  await item(page, renamedName).click({ button: "right" });
  const downloading = page.waitForEvent("download");
  await page.locator('button[aria-label="Download"]').click();
  const download = await downloading;
  expect(await download.failure()).toBeNull();
  const filename = await download.path();
  if (!filename) throw new Error("Browser download did not produce a file");
  expect(digest(await readFile(filename))).toBe(digest(edited));

  enterStage(testInfo, "delete");
  await item(page, renamedName).click({ button: "right" });
  await page.locator('button[aria-label="Delete"]').click();
  await page.locator('button[aria-label="Confirm-Delete"]').click();
  await expect(item(page, renamedName)).toHaveCount(0);
});

for (const filename of ["picture.png", "photo.jpg"]) {
  test(`decodes the actual ${filename} preview`, async ({ page }, testInfo) => {
    enterStage(testInfo, filename === "picture.png" ? "png" : "jpg");
    await item(page, filename).dblclick();
    await expect(page.locator("#previewer")).toBeVisible();
    await expect.poll(() => page.locator("#previewer img").evaluateAll((images) =>
      images.some((image) => image instanceof HTMLImageElement && image.complete && image.naturalWidth > 0)
    )).toBe(true);
  });
}

test("renders distinct nonblank XLSX content in the actual document viewer", async ({ page }, testInfo) => {
  enterStage(testInfo, "xlsx");
  const observations: Array<{ width: number; height: number; nonWhitePixels: number; pixelSha256: string }> = [];
  for (const filename of ["spreadsheet.xlsx", "spreadsheet-alternative.xlsx"]) {
    await page.goto(listing());
    const rendered = page.waitForResponse(response => {
      const requested = new URL(response.url());
      return response.request().method() === "GET" && requested.pathname === "/api/resources/preview" &&
        requested.searchParams.get("source") === source && requested.searchParams.get("path") === "/" + filename &&
        requested.searchParams.get("size") === "xlarge";
    });
    await item(page, filename).dblclick();
    const response = await rendered;
    expect(response.status()).toBe(200);
    expect(await response.finished()).toBeNull();
    await expect(page.locator("#previewer")).toBeVisible();
    // Select the full viewer image, never its cached thumbnail placeholder.
    const fullImage = page.locator('#previewer img.image-ex-img[src*="size=xlarge"]');
    await expect(fullImage).toHaveCount(1);
    const pixels = await fullImage.evaluate(async element => {
      if (!(element instanceof HTMLImageElement)) throw new Error("Document viewer image is missing");
      await element.decode();
      const width = element.naturalWidth;
      const height = element.naturalHeight;
      // The existing xlarge endpoint fits inside 1024 x 1024 pixels.
      if (width < 1 || height < 1 || width > 1024 || height > 1024) {
        throw new Error("Document viewer dimensions are invalid");
      }
      const canvas = document.createElement("canvas");
      canvas.width = width;
      canvas.height = height;
      const context = canvas.getContext("2d");
      if (!context) throw new Error("Document viewer pixels are unavailable");
      context.fillStyle = "white";
      context.fillRect(0, 0, width, height);
      context.drawImage(element, 0, 0);
      const imageData = context.getImageData(0, 0, width, height).data;
      let nonWhitePixels = 0;
      for (let offset = 0; offset < imageData.length; offset += 4) {
        if (imageData[offset] < 240 || imageData[offset + 1] < 240 || imageData[offset + 2] < 240) nonWhitePixels++;
      }
      const hash = await crypto.subtle.digest("SHA-256", imageData);
      const pixelSha256 = Array.from(new Uint8Array(hash), byte => byte.toString(16).padStart(2, "0")).join("");
      return { width, height, nonWhitePixels, pixelSha256 };
    });
    observations.push(pixels);
  }
  const output = process.env.FILEBROWSER_ACCEPTANCE_OUTPUT;
  if (!output) throw new Error("A private acceptance output directory is required");
  await mkdir(output, { recursive: true, mode: 0o700 });
  await writeFile(resolve(output, "xlsx-raster-evidence.json"),
    JSON.stringify({ schema: 1, rasters: observations }) + "\n", { mode: 0o600, flag: "wx" });
  for (const pixels of observations) expect(pixels.nonWhitePixels).toBeGreaterThan(10);
  // A shared placeholder image fails even if it decodes and is not blank.
  expect(observations[0].pixelSha256).not.toBe(observations[1].pixelSha256);
});

test("ordinary user logs out and loses access to the listing", async ({ page }, testInfo) => {
  enterStage(testInfo, "logout");
  await page.locator('button[aria-label="logout-button"]').click();
  await page.waitForURL("**/login**");
  await page.goto(listing());
  await page.waitForURL("**/login**");
});
