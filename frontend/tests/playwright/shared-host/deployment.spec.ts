import { createHash } from "node:crypto";
import { readFile, stat } from "node:fs/promises";
import { expect, test, type Page } from "@playwright/test";

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

test.beforeEach(async ({ page }) => {
  await page.goto("/login");
  await page.getByPlaceholder("Username").fill(credentials.username);
  await page.getByPlaceholder("Password").fill(credentials.password);
  await page.getByRole("button", { name: "Login", exact: true }).click();
  await page.waitForURL("**/files/**");
  await page.goto(listing());
  await expect(page.locator(".listing-items")).toBeVisible();
});

test("ordinary user uploads, edits, renames, downloads exact bytes and deletes", async ({ page }) => {
  const originalName = `ui-${Date.now()} 中文 空格.txt`;
  const renamedBase = `ui-${Date.now()} renamed`;
  const renamedName = renamedBase + ".txt";
  const original = Buffer.from("UI upload with Chinese filename.\n", "utf8");
  const edited = Buffer.from("Saved through the existing editor.\n", "utf8");

  await page.locator("#upload-input").setInputFiles({ name: originalName, mimeType: "text/plain", buffer: original });
  await expect(item(page, originalName)).toBeVisible({ timeout: 30000 });
  await item(page, originalName).dblclick();
  await expect(page.locator(".ace_text-layer")).toContainText("UI upload with Chinese filename.");
  await page.locator(".ace_content").click();
  await page.keyboard.press("ControlOrMeta+A");
  await page.keyboard.insertText(edited.toString("utf8"));
  const saved = page.waitForResponse((response) =>
    response.url().includes("/api/resources") && ["PUT", "POST"].includes(response.request().method()));
  await page.locator(".overflow-menu-button").click();
  await page.locator('button[aria-label="Save"]').click();
  expect((await saved).ok()).toBeTruthy();
  await page.goto(listing());

  await item(page, originalName).click({ button: "right" });
  await page.locator('button[aria-label="Rename"]').click();
  await page.locator('input[aria-label="New Name"]').fill(renamedBase);
  await page.locator('button[aria-label="Submit"]').click();
  await expect(item(page, renamedName)).toBeVisible();
  await expect(item(page, originalName)).toHaveCount(0);

  await item(page, renamedName).click({ button: "right" });
  const downloading = page.waitForEvent("download");
  await page.locator('button[aria-label="Download"]').click();
  const download = await downloading;
  expect(await download.failure()).toBeNull();
  const filename = await download.path();
  if (!filename) throw new Error("Browser download did not produce a file");
  expect(digest(await readFile(filename))).toBe(digest(edited));

  await item(page, renamedName).click({ button: "right" });
  await page.locator('button[aria-label="Delete"]').click();
  await page.locator('button[aria-label="Confirm-Delete"]').click();
  await expect(item(page, renamedName)).toHaveCount(0);
});

for (const filename of ["picture.png", "photo.jpg"]) {
  test(`decodes the actual ${filename} preview`, async ({ page }) => {
    await item(page, filename).dblclick();
    await expect(page.locator("#previewer")).toBeVisible();
    await expect.poll(() => page.locator("#previewer img").evaluateAll((images) =>
      images.some((image) => image instanceof HTMLImageElement && image.complete && image.naturalWidth > 0)
    )).toBe(true);
  });
}

test("ordinary user logs out and loses access to the listing", async ({ page }) => {
  await page.locator('button[aria-label="logout-button"]').click();
  await page.waitForURL("**/login**");
  await page.goto(listing());
  await page.waitForURL("**/login**");
});
