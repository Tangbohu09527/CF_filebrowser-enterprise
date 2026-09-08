import { writeFile } from "node:fs/promises";
import type { Browser, Page } from "@playwright/test";
import { expect, firefox } from "@playwright/test";
import { openContextMenuHelper, openShareAndExpectPath } from "./test-setup";

// Perform authentication and store auth state
async function globalSetup() {
  const browser: Browser = await firefox.launch();
  const context = await browser.newContext();
  const page: Page = await context.newPage();

  await page.goto("http://127.0.0.1/login");
  await page.getByPlaceholder("Username").fill("admin");
  await page.getByPlaceholder("Password").fill("admin");
  await page.getByRole("button", { name: "Login" }).click();
  await page.waitForURL("**/files/", { timeout: 1000 });

  const cookies = await context.cookies();
  expect(cookies.find((c) => c.name === "filebrowser_quantum_jwt")?.value).toBeDefined();
  await expect(page).toHaveTitle("Graham's Filebrowser - Files - playwright-files");

  await page.waitForURL("**/files/playwright%20+%20files/", { timeout: 1000 });

  await expect(page).toHaveTitle("Graham's Filebrowser - Files - playwright-files");

  // Create a share of folder
  await page.locator('a[aria-label="myfolder"]').waitFor({ state: 'visible' });
  await openShareAndExpectPath(page, 'Path: /myfolder/', async () => {
    await page.locator('a[aria-label="myfolder"]').click({ button: "right" });
    await page.locator('.selected-count-header').waitFor({ state: 'visible' });
    await expect(page.locator('.selected-count-header')).toHaveText('1');
    await page.locator('button[aria-label="Share"]').click();
  });
  await page.locator('button[aria-label="Share-Confirm"]').click();
  await expect(page.locator("div[aria-label='share-prompt'] .card-content table tbody tr:not(:has(th))")).toHaveCount(1);
  const shareHash = await page.locator("div[aria-label='share-prompt'] .card-content table tbody tr:not(:has(th)) td").first().textContent();
  if (!shareHash) {
    throw new Error("Failed to retrieve shareHash");
  }
  // Store shareHash in localStorage
  await page.evaluate((hash) => {
    localStorage.setItem('shareHash', hash);
  }, shareHash);

  await page.goto("http://127.0.0.1/files/playwright%20%2B%20files/", { timeout: 1000 });
  // Create a share of file
  await page.locator('a[aria-label="1file1.txt"]').waitFor({ state: 'visible' });
  await openShareAndExpectPath(page, 'Path: /1file1.txt', async () => {
    await page.locator('a[aria-label="1file1.txt"]').click({ button: "right" });
    await page.locator('.selected-count-header').waitFor({ state: 'visible' });
    await expect(page.locator('.selected-count-header')).toHaveText('1');
    await page.locator('button[aria-label="Share"]').click();
  });
  await page.locator('button[aria-label="Share-Confirm"]').click();
  await expect(page.locator("div[aria-label='share-prompt'] .card-content table tbody tr:not(:has(th))")).toHaveCount(1);
  const shareHashFile = await page.locator("div[aria-label='share-prompt'] .card-content table tbody tr:not(:has(th)) td").first().textContent();
  if (!shareHashFile) {
    throw new Error("Failed to retrieve shareHash");
  }
  // Store shareHash in localStorage
  await page.evaluate((hash) => {
    localStorage.setItem('shareHashFile', hash);
  }, shareHashFile);

  // Create a share of root folder "/".
  const pageErrorCounts = { type: 0, reference: 0, syntax: 0, other: 0 };
  const recordRootShareError = (error: Error) => {
    const category = error.name === "TypeError" ? "type" :
      error.name === "ReferenceError" ? "reference" : error.name === "SyntaxError" ? "syntax" : "other";
    pageErrorCounts[category] += 1;
  };
  page.on("pageerror", recordRootShareError);
  try {
    await page.goto("http://127.0.0.1/files/playwright%20%2B%20files/", { timeout: 1000 });
    await page.locator('a[aria-label="share"]').waitFor({ state: 'visible' });
    let rootShareStatus: number | undefined;
    await openShareAndExpectPath(page, 'Path: /', async () => {
      await openContextMenuHelper(page);
      const menu = page.locator("#context-menu:visible");
      await expect(menu).toBeVisible({ timeout: 2000 });
      await expect(menu.locator(".selected-count-header")).toHaveCount(0, { timeout: 2000 });
      const [response] = await Promise.all([
        page.waitForResponse(response => {
          const url = new URL(response.url());
          return response.request().method() === "GET" && url.pathname === "/api/share" &&
            url.searchParams.get("path") === "/" &&
            url.searchParams.get("source") === "playwright + files";
        }, { timeout: 2000 }),
        menu.getByRole("button", { name: "Share", exact: true }).click({ timeout: 2000 }),
      ]);
      rootShareStatus = response.status();
    });
    // A visible prompt must not let the helper's retry hide a missing/rejected GET.
    expect(rootShareStatus).toBe(200);
  } catch (error) {
    const pathname = new URL(page.url()).pathname;
    const fixturePaths = ["/files/", "/files/playwright%20%2B%20files/", "/files/playwright%20+%20files/", "/login"];
    console.error("Root share setup diagnostics", JSON.stringify({
      pageErrorCounts,
      visiblePromptCount: await page.locator('.floating-window[aria-label$="-prompt"]:visible').count(),
      visibleSharePromptCount: await page.locator('div[aria-label="share-prompt"]:visible').count(),
      pathname: fixturePaths.includes(pathname) ? pathname : "<other>",
    }));
    throw error;
  } finally {
    page.off("pageerror", recordRootShareError);
  }
  // Enable the current V1 Create and Modify controls through the visible sliders.
  const capabilityEditor = page.getByTestId("configured-capabilities");
  for (const capability of ["create", "modify"]) {
    const input = capabilityEditor.locator(`input[aria-label="${capability}"]`);
    await input.waitFor({ state: "attached" });
    await expect(input).toBeEnabled();
    await expect(input).not.toBeChecked();
    await capabilityEditor.locator(`input[aria-label="${capability}"] + .slider`).click();
    await expect(input).toBeChecked();
  }

  await page.locator('button[aria-label="Share-Confirm"]').click();
  await expect(page.locator("div[aria-label='share-prompt'] .card-content table tbody tr:not(:has(th))")).toHaveCount(1);
  const rootShareHash = await page.locator("div[aria-label='share-prompt'] .card-content table tbody tr:not(:has(th)) td").first().textContent();
  if (!rootShareHash) {
    throw new Error("Failed to retrieve rootShareHash");
  }
  // Store shareHash in localStorage
  await page.evaluate((hash) => {
    localStorage.setItem('rootShareHash', hash);
  }, rootShareHash);

  // Anonymous share tests: same share hashes in localStorage, no JWT cookies.
  await writeFile(
    "./sharePrepStorage.json",
    JSON.stringify(
      {
        cookies: [],
        origins: [
          {
            origin: "http://127.0.0.1",
            localStorage: [
              { name: "shareHash", value: shareHash },
              { name: "shareHashFile", value: shareHashFile },
              { name: "rootShareHash", value: rootShareHash },
            ],
          },
        ],
      },
      null,
      2,
    ),
    "utf-8",
  );

  await context.storageState({ path: "./loginAuth.json" });
  await browser.close();
}

export default globalSetup;
