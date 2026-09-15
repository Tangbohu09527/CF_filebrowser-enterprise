import type { Browser, Page } from "@playwright/test";
import { expect, firefox } from "@playwright/test";

// Perform authentication and store auth state
async function globalSetup() {
  const browser: Browser = await firefox.launch();
  const context = await browser.newContext();
  const page: Page = await context.newPage();

  // Set basic auth credentials for protected /subpath route
  await page.setExtraHTTPHeaders({
    'Authorization': `Basic ZGVtby0xMjcuMC4wLjE6U2VjdXJlUGFzczEyMyE=`
  });

  await page.goto("http://127.0.0.1/subpath/");
  try {
    await expect(page).toHaveTitle("Graham's Filebrowser - Files - demo-127.0.0.1");
  } catch (titleError) {
    // Keep raw API bodies and browser credentials inside this same page context.
    // The proxy fixture's unnamed source is named from its basename by config.go;
    // createUserDir appends the proxy username to its default root scope.
    const identity = await page.evaluate(async () => {
      const result = { status: 0, identityMatches: false, permissionsMatch: false, scopeMatches: false };
      const controller = new AbortController();
      const deadline = setTimeout(() => controller.abort(), 10000);
      try {
        const response = await fetch("/subpath/api/users?id=self", { credentials: "same-origin", signal: controller.signal });
        result.status = response.status;
        const user = await response.json();
        result.identityMatches = user?.username === "demo-127.0.0.1" && user?.loginMethod === "proxy" &&
          user?.permissions?.admin === false;
        const expected = { admin: false, api: false, modify: true, share: true, download: true, create: true,
          browse: true, preview: true, delete: false, realtime: false };
        result.permissionsMatch = Object.entries(expected).every(([name, allowed]) => user?.permissions?.[name] === allowed);
        result.scopeMatches = Array.isArray(user?.scopes) && user.scopes.length === 1 &&
          user.scopes[0]?.name === "playwright-files" && user.scopes[0]?.scope === "/demo-127.0.0.1";
      } catch {
        // A transport/JSON failure is represented only by fixed false values.
      } finally {
        clearTimeout(deadline);
      }
      return result;
    }).catch(() => ({ status: 0, identityMatches: false, permissionsMatch: false, scopeMatches: false }));
    expect(identity.status, "[proxy-setup:self-status]").toBe(200);
    expect(identity.identityMatches, "[proxy-setup:self-identity]").toBe(true);
    expect(identity.permissionsMatch, "[proxy-setup:self-permissions]").toBe(true);
    expect(identity.scopeMatches, "[proxy-setup:self-scope]").toBe(true);

    const root = await page.evaluate(async () => {
      const result = { status: 0, directoryMatches: false };
      const controller = new AbortController();
      const deadline = setTimeout(() => controller.abort(), 10000);
      try {
        const response = await fetch("/subpath/api/resources?source=playwright-files&path=%2F", { credentials: "same-origin", signal: controller.signal });
        result.status = response.status;
        const resource = await response.json();
        result.directoryMatches = resource?.type === "directory" && resource?.name === "demo-127.0.0.1" &&
          resource?.path === "/";
      } catch {
        // Never propagate a response body or an arbitrary browser error.
      } finally {
        clearTimeout(deadline);
      }
      return result;
    }).catch(() => ({ status: 0, directoryMatches: false }));
    expect(root.status, "[proxy-setup:source-status]").toBe(200);
    expect(root.directoryMatches, "[proxy-setup:source-directory]").toBe(true);

    // Successful diagnostics never retry or mask the original title failure.
    throw titleError;
  }

  // Create a share of folder
  await page.locator('button[aria-label="File-Actions"]').waitFor({ state: 'visible' });
  await page.locator('button[aria-label="File-Actions"]').click();
  await page.locator('button[aria-label="Share"]').click();
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

  await context.storageState({ path: "./loginAuth.json" });
  await browser.close();
}

export default globalSetup;
