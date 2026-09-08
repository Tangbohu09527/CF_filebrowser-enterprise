import { checkForNotification, expect, test } from "../test-setup";

/** Move/Copy prompt path line: PathPickerButton shows `/path (source)`; noauth config names the tree `exclude`. */
const copyDestLabel = (page: import("@playwright/test").Page) =>
  page.locator('div[aria-label="copy-prompt"] .move-copy-path-picker');

const NOAUTH_COPY_SOURCE = "exclude";

test("info from listing", async({ page, checkForErrors }) => {
  await page.goto("/files/");
  await expect(page).toHaveTitle("Graham's Filebrowser - Files - playwright-files");
  await page.locator('a[aria-label="file.tar.gz"]').waitFor({ state: 'visible' });
  await page.locator('a[aria-label="file.tar.gz"]').click( { button: "right" });
  await page.locator('.selected-count-header').waitFor({ state: 'visible' });
  await expect(page.locator('.selected-count-header')).toHaveText('1');
  await page.locator('button[aria-label="Info"]').click();
  await expect(page.locator('span[aria-label="info display name"]')).toHaveText('file.tar.gz');
  checkForErrors();
});

test("info from search", async({ page, checkForErrors }) => {
  await page.goto("/files/");
  await expect(page).toHaveTitle("Graham's Filebrowser - Files - playwright-files");
  await page.locator('#search-bar-input').click()
  await page.locator('#search-input').fill('file.tar.gz');
  await expect(page.locator('#result-list ul li.search-entry')).toHaveCount(1);
  await page.locator('li[aria-label="file.tar.gz"]').click({ button: "right" });
  await page.locator('button[aria-label="Info"]').click();
  await expect(page.locator('span[aria-label="info display name"]')).toHaveText('file.tar.gz');
  checkForErrors();
})

test("open from search", async({ page, checkForErrors }) => {
  await page.goto("/files/");
  await expect(page).toHaveTitle("Graham's Filebrowser - Files - playwright-files");
  await page.locator('#search-bar-input').click()
  await page.locator('#search-input').fill('file.tar.gz');
  await expect(page.locator('#result-list ul li.search-entry')).toHaveCount(1);
  await page.locator('li[aria-label="file.tar.gz"]').click();
  await expect(page).toHaveTitle("Graham's Filebrowser - Files - file.tar.gz");
  await expect(page.locator('#previewer')).toContainText('Preview is not available for this file.');
  checkForErrors();
})

test("2x copy from listing to new folder", async({ page, checkForErrors }) => {
  const copyAndCheck = async (fromPath: string, toPath: string, currentDirectory: string) => {
    const item = { fromSource: NOAUTH_COPY_SOURCE, fromPath, toSource: NOAUTH_COPY_SOURCE, toPath };
    const refreshRequests = new Set<import("@playwright/test").Request>();
    let copyRequestStarted = false;
    const trackRefresh = (request: import("@playwright/test").Request) => {
      const requestURL = new URL(request.url());
      if (requestURL.pathname !== "/files/api/resources") return;
      if (request.method() === "PATCH") copyRequestStarted = true;
      const requestPath = requestURL.searchParams.get("path")?.replace(/\/+$/, "") || "/";
      const expectedPath = currentDirectory.replace(/\/+$/, "") || "/";
      if (copyRequestStarted && request.method() === "GET" &&
          requestURL.searchParams.get("source") === NOAUTH_COPY_SOURCE &&
          requestPath === expectedPath &&
          !requestURL.searchParams.has("content") && !requestURL.searchParams.has("metadata")) {
        refreshRequests.add(request);
      }
    };
    page.on("request", trackRefresh);
    try {
      const copied = page.waitForResponse(response =>
        response.request().method() === "PATCH" &&
        new URL(response.url()).pathname === "/files/api/resources"
      );
      // Track only refreshes started after this copy PATCH, excluding already in-flight GETs.
      const refreshed = page.waitForResponse(response => refreshRequests.has(response.request()));
      await page.locator('button[aria-label="Copy"]').click();
      const response = await copied;
      expect(response.request().postDataJSON()).toEqual({
        items: [item], action: "copy", overwrite: false, rename: false,
      });
      expect(response.status()).toBe(200);
      expect(await response.json()).toEqual({ succeeded: [item], failed: [] });
      const refreshResponse = await refreshed;
      expect(refreshResponse.status()).toBe(200);
      expect(await refreshResponse.finished()).toBeNull();
    } finally {
      page.off("request", trackRefresh);
    }
  };
  let failedRequestCount = 0;
  const onRequestFailed = (request: import("@playwright/test").Request) => {
    if (++failedRequestCount > 8) return;
    const pathname = new URL(request.url()).pathname;
    const endpoint = pathname === "/files/api/resources" ? "resources" :
      pathname.startsWith("/files/api/media") ? "media" : "other";
    const method = ["GET", "POST", "PATCH", "PUT", "DELETE", "HEAD", "OPTIONS"].includes(request.method()) ?
      request.method() : "OTHER";
    const errorText = request.failure()?.errorText || "";
    const category = /abort|cancel/i.test(errorText) ? "aborted" :
      /network|fetch|connect|resolve|timed_out/i.test(errorText) ? "network" : "other";
    console.log("Copy request failure", { endpoint, method, category });
  };
  page.on("requestfailed", onRequestFailed);
  try {
    await page.goto("/files/");
    await expect(page).toHaveTitle("Graham's Filebrowser - Files - playwright-files");
    await page.locator('a[aria-label="copyme.txt"]').waitFor({ state: 'visible' });
    await page.locator('a[aria-label="copyme.txt"]').click( { button: "right" });
    await page.locator('.selected-count-header').waitFor({ state: 'visible' });
    await expect(page.locator('.selected-count-header')).toHaveText('1');
    await page.locator('button[aria-label="Copy file"]').click();
    await expect(copyDestLabel(page)).toHaveText(`/ (${NOAUTH_COPY_SOURCE})`);
    await expect(page.locator('div[aria-label="copy-prompt"] .listing-item[aria-selected="true"]')).toHaveCount(0);
    await page.locator('div[aria-label="copy-prompt"] .listing-item[aria-label="myfolder"]').dblclick();
    await expect(copyDestLabel(page)).toHaveText(`/myfolder/ (${NOAUTH_COPY_SOURCE})`);
    await copyAndCheck("/copyme.txt", "/myfolder/copyme.txt", "/");
    await checkForNotification(page, "Files copied successfully!");
    await page.goto("/files/files/exclude/myfolder/");
    await expect(page).toHaveTitle("Graham's Filebrowser - Files - myfolder");
    // verify exists and copy again
    await page.locator('a[aria-label="copyme.txt"]').waitFor({ state: 'visible' });

    // create new directory
    // Ensure .listing-items is visible
    await page.locator('.listing-items').click({ button: "right" });
    await page.locator('button[aria-label="New folder"]').waitFor({ state: 'visible' });
    await page.locator('button[aria-label="New folder"]').click();
    await page.locator('input[aria-label="New Folder Name"]').waitFor({ state: 'visible' });
    await page.locator('input[aria-label="New Folder Name"]').fill('newfolder');
    await page.locator('button[aria-label="Create"]').click();
    // Wait for notification and click "Go to item" button
    await page.locator('.notification-buttons .button').waitFor({ state: 'visible' });
    await page.locator('.notification-buttons .button').click();
    await expect(page).toHaveTitle(/.* - newfolder/);
    await page.goBack();
    await expect(page).toHaveTitle(/.* - myfolder/);

    await page.locator('a[aria-label="copyme.txt"]').click( { button: "right" });
    await page.locator('.selected-count-header').waitFor({ state: 'visible' });
    await expect(page.locator('.selected-count-header')).toHaveText('1');
    await page.locator('button[aria-label="Copy file"]').click();
    await expect(copyDestLabel(page)).toHaveText(`/myfolder (${NOAUTH_COPY_SOURCE})`);
    await page.locator('div[aria-label="copy-prompt"] .listing-item[aria-label="newfolder"]').dblclick();
    await expect(copyDestLabel(page)).toHaveText(`/myfolder/newfolder/ (${NOAUTH_COPY_SOURCE})`);
    await copyAndCheck("/myfolder/copyme.txt", "/myfolder/newfolder/copyme.txt", "/myfolder/");
    await checkForNotification(page, "Files copied successfully!");
    await page.goto("/files/files/exclude/myfolder/newfolder/");
    await expect(page).toHaveTitle(/.* - newfolder/);
    await expect(page.locator('a[aria-label="copyme.txt"]')).toBeVisible();
    checkForErrors();
  } finally {
    page.off("requestfailed", onRequestFailed);
  }
})

test("delete file", async({ page, checkForErrors }) => {
  await page.goto("/files/");
  await expect(page).toHaveTitle("Graham's Filebrowser - Files - playwright-files");
  await page.locator('a[aria-label="deleteme.txt"]').waitFor({ state: 'visible' });
  await page.locator('a[aria-label="deleteme.txt"]').click({ button: "right" });
  await page.locator('.selected-count-header').waitFor({ state: 'visible' });
  await expect(page.locator('.selected-count-header')).toHaveText('1');
  await page.locator('button[aria-label="Delete"]').click();
  await expect( page.locator('.card-content')).toContainText('/deleteme.txt');
  await page.locator('button[aria-label="Confirm-Delete"]').click();
  await checkForNotification(page, "Deleted successfully!");

  // verify its no longer in index via search
  await page.locator('#search-bar-input').click()
  await page.locator('#search-input').fill('deleteme.txt');
  await expect(page.locator('#result-list ul li.search-entry')).toHaveCount(0);
  checkForErrors();
})

test("delete nested file prompt", async({ page, checkForErrors }) => {
  await page.goto("/files/files/exclude/folder%23hash/");
  await expect(page).toHaveTitle("Graham's Filebrowser - Files - folder#hash");
  await page.locator('a[aria-label="file#.sh"]').waitFor({ state: 'visible' });
  await page.locator('a[aria-label="file#.sh"]').click({ button: "right" });
  await page.locator('.selected-count-header').waitFor({ state: 'visible' });
  await expect(page.locator('.selected-count-header')).toHaveText('1');
  await page.locator('button[aria-label="Delete"]').click();
  await expect(page.locator('.card-content')).toContainText('/folder#hash/file#.sh');
  checkForErrors();
})

test("rename file", async({ page, checkForErrors }) => {
  await page.goto("/files/");
  await expect(page).toHaveTitle("Graham's Filebrowser - Files - playwright-files");
  await page.locator('a[aria-label="renameme.txt"]').waitFor({ state: 'visible' });
  await page.locator('a[aria-label="renameme.txt"]').click({ button: "right" });
  await page.locator('.selected-count-header').waitFor({ state: 'visible' });
  await expect(page.locator('.selected-count-header')).toHaveText('1');
  await page.locator('button[aria-label="Rename"]').click();
  await page.locator('input[aria-label="New Name"]').waitFor({ state: 'visible' });
  await page.locator('input[aria-label="New Name"]').fill('renamed.txt');
  await page.locator('button[aria-label="Submit"]').click();
  await checkForNotification(page, "Item renamed successfully!");

  // verify its no longer in index via search
  await page.locator('#search-bar-input').click()
  await page.locator('#search-input').fill('renameme.txt');
  await expect(page.locator('#result-list ul li.search-entry')).toHaveCount(0);
  checkForErrors();
})

test("create a file with the same name as a directory", async({ page, checkForErrors, openContextMenu }) => {
  await page.goto("/files/");
  await expect(page).toHaveTitle("Graham's Filebrowser - Files - playwright-files");
  await openContextMenu();
  await page.locator('button[aria-label="New file"]').click();
  await page.locator('button[aria-label="Create"]').click();
  await page.locator('input[aria-label="FileName Field"]').waitFor({ state: 'visible' });
  await page.locator('input[aria-label="FileName Field"]').fill('mytest');
  await page.locator('button[aria-label="Create"]').click();
  await page.locator('a[aria-label="mytest"]').waitFor({ state: 'visible' });
  await page.locator('a[aria-label="mytest"]').click({ button: "right" });
  await page.locator('.selected-count-header').waitFor({ state: 'visible' });
  await expect(page.locator('.selected-count-header')).toHaveText('1');
  await page.locator('button[aria-label="Delete"]').click();
  await expect(page.locator('.card-content')).toContainText('/mytest');
  await page.locator('button[aria-label="Confirm-Delete"]').click();
  await checkForNotification(page, "Deleted successfully!");
  await openContextMenu();
  await page.locator('button[aria-label="New folder"]').click();
  await page.locator('input[aria-label="New Folder Name"]').waitFor({ state: 'visible' });
  await page.locator('input[aria-label="New Folder Name"]').fill('mytest');
  await page.locator('button[aria-label="Create"]').click();
  await page.locator('a[aria-label="mytest"]').waitFor({ state: 'visible' });
  await page.locator('a[aria-label="mytest"]').dblclick();
  await expect(page).toHaveTitle("Graham's Filebrowser - Files - mytest");
  checkForErrors();
})
