import type { Page, Request } from "@playwright/test";
import { test as base, expect } from "@playwright/test";

/**
 * Standalone helper function to open the context menu (File-Actions button)
 * Can be used in both test fixtures and global setup
 */
export async function openContextMenuHelper(page: Page): Promise<void> {
  // First, wait for the page to be in a state where file actions can be shown
  // This marker element is always present when conditions are met, regardless of transition state
  const readyMarker = page.locator('[data-testid="file-actions-ready"]');
  
  try {
    await readyMarker.waitFor({ state: 'attached', timeout: 5000 });
    
    // Check if the button should be hidden
    const isHidden = await readyMarker.getAttribute('data-hidden');
    if (isHidden === 'true') {
      throw new Error('File actions button is hidden (user does not have create permissions or is on invalid share)');
    }
  } catch (error: unknown) {
    if (error instanceof Error && error.message.includes('hidden')) {
      throw error;
    }
    const originalMessage = error instanceof Error ? error.message : String(error);
    throw new Error(`File actions are not available on this page. Check that you are on a listing view with appropriate permissions. Original error: ${originalMessage}`);
  }
  
  // Now wait for the actual button to be visible (accounting for transition)
  const fileActionsButton = page.locator('[data-testid="file-actions-button"]');
  await fileActionsButton.waitFor({ state: 'visible', timeout: 5000 });
  await fileActionsButton.click();
}

/**
 * Opens the share dialog and asserts the path, retrying on transient UI timing failures.
 */
export async function openShareAndExpectPath(
  page: Page,
  expectedPathText: string,
  openShare: () => Promise<void>,
  options?: { timeout?: number },
): Promise<void> {
  const timeout = options?.timeout ?? 20000;
  const sharePath = page.locator('div[aria-label="share-path"]');
  const sharePrompt = page.locator("div[aria-label='share-prompt']");

  await expect(async () => {
    if (!(await sharePrompt.isVisible())) {
      await openShare();
    }
    await expect(sharePath).toHaveText(expectedPathText, { timeout: 2000 });
  }).toPass({ timeout });
}

export const test = base.extend<{
  checkForErrors: (expectedConsoleErrors?: number, expectedApiErrors?: number) => void;
  openContextMenu: () => Promise<void>;
  theme: 'light' | 'dark';
  checkForNotification: (message: string | RegExp) => Promise<import('@playwright/test').Locator>;
}>({
  checkForErrors: async ({ page }, use) => {
    const { checkForErrors, dispose } = setupErrorTracking(page);
    try {
      await use(checkForErrors);
    } finally {
      dispose();
    }
  },
  openContextMenu: async ({ page }, use) => {
    await use(async () => {
      await openContextMenuHelper(page);
    });
  },
  theme: async ({}, use, testInfo) => {
    const theme = (testInfo.project.use as { theme?: 'light' | 'dark' }).theme || 'dark';
    await use(theme);
  },
  checkForNotification: async ({ page }, use) => {
    await use(async (message: string | RegExp) => {
      return await checkForNotification(page, message);
    });
  },
});

// Error tracking function
export function setupErrorTracking(page: Page) {
  const consoleErrors: string[] = [];
  const failedResponses: { url: string; status: number }[] = [];
  // Keep only fixed categories: failed fetches may have no HTTP response.
  // Request URLs, credentials, failure text and payloads are never retained here.
  const requestFailures: { endpoint: string; method: string; resourceType: string; category: string; navigation: boolean }[] = [];
  let requestFailuresTruncated = false;
  const onRequestFailed = (request: Request) => {
    if (requestFailures.length >= 16) {
      requestFailuresTruncated = true;
      return;
    }
    try {
      const navigation = request.isNavigationRequest() === true;
      let pathname = "";
      try {
        // Backend bases: noauth/screenshots=/files/, proxy=/subpath, others=/.
        // Strip only their exact API prefixes; UI and public paths stay unknown.
        pathname = new URL(request.url()).pathname.replace(/^\/(?:files|subpath)(?=\/api(?:\/|$))/, "");
      } catch {
        // An unparseable address is reported only as an unknown endpoint.
      }
      const endpoint = navigation ? "other" : pathname === "/api/resources/preview" ? "preview" :
        pathname === "/api/resources" ? "resources" :
        pathname === "/api/events" ? "events" :
        /^\/api\/tools\/fileWatcher(?:\/sse)?$/.test(pathname) ? "file-watcher" :
        /^\/api\/auth(?:\/|$)/.test(pathname) ? "auth" :
        /^\/api\/media(?:\/|$)/.test(pathname) ? "media" :
        /^\/api\/tools(?:\/|$)/.test(pathname) ? "tools" :
        /^\/api\/users(?:\/|$)/.test(pathname) ? "users" :
        /^\/api\/share(?:\/|$)/.test(pathname) ? "share" :
        /^\/api\/settings(?:\/|$)/.test(pathname) ? "settings" :
        /^\/api(?:\/|$)/.test(pathname) ? "api-other" : "other";
      const requestMethod = request.method();
      const method = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"].includes(requestMethod) ? requestMethod : "OTHER";
      const requestResourceType = request.resourceType();
      const resourceType = ["document", "stylesheet", "image", "media", "font", "script", "texttrack", "xhr", "fetch", "eventsource", "websocket", "manifest", "other"].includes(requestResourceType) ? requestResourceType : "other";
      const failure = request.failure()?.errorText || "";
      const category = /abort|cancel/i.test(failure) ? "aborted" :
        /timeout|timed_out/i.test(failure) ? "timeout" :
        /unknown_host|name_not_resolved/i.test(failure) ? "dns" :
        /connection_refused/i.test(failure) ? "refused" :
        /net_reset|connection_reset/i.test(failure) ? "reset" :
        /ssl|tls|cert|sec_error/i.test(failure) ? "tls" :
        /network|fetch|net_error|connection/i.test(failure) ? "network" : "other";
      requestFailures.push({ endpoint, method, resourceType, category, navigation });
    } catch {
      // A diagnostic getter failure must not alter the original error checks.
      requestFailures.push({ endpoint: "other", method: "OTHER", resourceType: "other", category: "unavailable", navigation: false });
    }
  };
  page.on("requestfailed", onRequestFailed);

  // Track console errors
  page.on("console", async (message) => {
    if (message.type() === "error") {
      const errorText = message.text();
      const args = message.args();

      // Try to extract more detailed error information
      let detailedError = errorText;

      if (args.length > 0) {
        try {
          // Get the first argument which usually contains the error object
          const firstArg = await args[0].jsonValue().catch(() => null);

          if (firstArg && typeof firstArg === 'object') {
            if (firstArg.stack) {
              // If we have a stack trace, use it
              detailedError = firstArg.stack;
            } else if (firstArg.message) {
              // Otherwise use the message if available
              detailedError = `${firstArg.name || 'Error'}: ${firstArg.message}`;
            }
          }
        } catch (_e) {
          // If we can't extract detailed info, try to get string representation of args
          try {
            const argsText = await Promise.all(
              args.map(async (arg) => {
                try {
                  return await arg.evaluate((obj) => {
                    if (obj && typeof obj === 'object' && obj.stack) {
                      return obj.stack;
                    }
                    return String(obj);
                  });
                } catch {
                  return '[Unable to serialize]';
                }
              })
            );

            const combinedArgs = argsText.join(' ');
            if (combinedArgs.trim() && combinedArgs !== errorText) {
              detailedError = combinedArgs;
            }
          } catch {
            // Fallback to original text
            detailedError = errorText;
          }
        }
      }

      consoleErrors.push(detailedError);
    }
  });

  // Track failed API calls (304 Not Modified is expected for cached preview requests)
  page.on("response", (response) => {
    const status = response.status();
    if (status === 304 || response.ok()) {
      return;
    }
    failedResponses.push({
      url: response.url(),
      status,
    });
  });

  return {
    checkForErrors: (expectedConsoleErrors = 0, expectedApiErrors = 0) => {
      if (consoleErrors.length !== expectedConsoleErrors || failedResponses.length !== expectedApiErrors) {
        console.error("Playwright request failure diagnostics", JSON.stringify({
          schema: 1, failures: requestFailures, truncated: requestFailuresTruncated,
        }));
      }
      if (consoleErrors.length !== expectedConsoleErrors) {
        console.error(`\n=== Unexpected Console Errors (Expected: ${expectedConsoleErrors}, Got: ${consoleErrors.length}) ===`);
        consoleErrors.forEach((error, index) => {
          console.error(`\nError ${index + 1}:`);
          console.error(error);
          console.error('---');
        });
        console.error('=== End Console Errors ===\n');
      }

      if (failedResponses.length !== expectedApiErrors) {
        console.error(`\n=== Unexpected Failed API Calls (Expected: ${expectedApiErrors}, Got: ${failedResponses.length}) ===`);
        failedResponses.forEach((response, index) => {
          console.error(`\nFailed Request ${index + 1}: ${response.status} - ${response.url}`);
        });
        console.error('=== End Failed API Calls ===\n');
      }

      expect(consoleErrors).toHaveLength(expectedConsoleErrors);
      expect(failedResponses).toHaveLength(expectedApiErrors);
    },
    dispose: () => page.off("requestfailed", onRequestFailed),
  };
}

/**
 * Helper function to check for a notification or toast with the given message
 * @param page - Playwright page object
 * @param message - Expected message text (string or RegExp)
 * @returns Locator for the matching notification or toast message
 */
export async function checkForNotification(page: Page, message: string | RegExp): Promise<import('@playwright/test').Locator> {
  // Check both notifications and toasts
  const notificationMessage = page.locator('.notification-message');
  const toastMessage = page.locator('.toast-message');
  const allMessages = page.locator('.notification-message, .toast-message');

  try {
    // Wait for a notification or toast containing the message to appear
    let matchingMessage: import('@playwright/test').Locator | null = null;

    if (typeof message === 'string') {
      // For string matching, use text content filter
      matchingMessage = allMessages.filter({ hasText: message }).first();
    } else {
      // For RegExp, we need to check all and find the match
      // Wait for at least one notification or toast first
      await allMessages.first().waitFor({ state: 'visible', timeout: 5000 });

      // Then check all messages
      const count = await allMessages.count();
      for (let i = 0; i < count; i++) {
        const messageElement = allMessages.nth(i);
        const text = await messageElement.textContent();
        if (text && message.test(text)) {
          matchingMessage = messageElement;
          break;
        }
      }
    }

    if (matchingMessage) {
      // Wait for it to be visible (with retry logic)
      await matchingMessage.waitFor({ state: 'visible', timeout: 5000 });
      return matchingMessage;
    }

    // If no match found, get all messages for error reporting
    const [notificationTexts, toastTexts] = await Promise.all([
      notificationMessage.allTextContents(),
      toastMessage.allTextContents(),
    ]);
    const allTexts = {
      notifications: notificationTexts,
      toasts: toastTexts,
    };
    const errorMessage = `Message "${message}" not found. Current messages: ${JSON.stringify(allTexts)}`;
    throw new Error(errorMessage);

  } catch (error: unknown) {
    // Handle page closed/navigation errors gracefully
    if (error instanceof Error && (error.message.includes('Target page') || error.message.includes('closed'))) {
      // Try to get current messages before page closed
      try {
        const [notificationTexts, toastTexts] = await Promise.all([
          notificationMessage.allTextContents(),
          toastMessage.allTextContents(),
        ]);
        const allTexts = {
          notifications: notificationTexts,
          toasts: toastTexts,
        };
        throw new Error(`Message check failed: page was closed or navigated. Expected: "${message}". Found before page closed: ${JSON.stringify(allTexts)}`);
      } catch {
        throw new Error(`Message check failed: page was closed or navigated before message could be checked. Expected: "${message}"`);
      }
    }

    // If no messages found, provide helpful error
    if (error instanceof Error && error.message.includes('waiting for')) {
      try {
        const [notificationTexts, toastTexts] = await Promise.all([
          notificationMessage.allTextContents(),
          toastMessage.allTextContents(),
        ]);
        const allTexts = {
          notifications: notificationTexts,
          toasts: toastTexts,
        };
        const totalCount = notificationTexts.length + toastTexts.length;
        const errorMessage = totalCount === 0
          ? 'No notifications or toasts found on the page.'
          : `No matching message found. Current messages: ${JSON.stringify(allTexts)}`;
        throw new Error(`Message "${message}" not found. ${errorMessage}`);
      } catch (countError: unknown) {
        if (countError instanceof Error && (countError.message.includes('Target page') || countError.message.includes('closed'))) {
          throw error;
        }
        throw countError;
      }
    }

    throw error;
  }
}

/**
 * Helper function to check specifically for a toast message
 * Use this when you want to verify that a toast (not a notification) was shown
 * @param page - Playwright page object
 * @param message - Expected message text (string or RegExp)
 * @returns Locator for the matching toast message
 */
export async function checkForToast(page: Page, message: string | RegExp): Promise<import('@playwright/test').Locator> {
  const toastMessage = page.locator('.toast-message');

  try {
    let matchingToast: import('@playwright/test').Locator | null = null;

    if (typeof message === 'string') {
      matchingToast = toastMessage.filter({ hasText: message }).first();
    } else {
      await toastMessage.first().waitFor({ state: 'visible', timeout: 5000 });
      const count = await toastMessage.count();
      for (let i = 0; i < count; i++) {
        const toast = toastMessage.nth(i);
        const text = await toast.textContent();
        if (text && message.test(text)) {
          matchingToast = toast;
          break;
        }
      }
    }

    if (matchingToast) {
      await matchingToast.waitFor({ state: 'visible', timeout: 5000 });
      return matchingToast;
    }

    const allToasts = await toastMessage.allTextContents();
    throw new Error(`Toast with message "${message}" not found. Current toasts: ${JSON.stringify(allToasts)}`);

  } catch (error: unknown) {
    if (error instanceof Error && (error.message.includes('Target page') || error.message.includes('closed'))) {
      throw new Error(`Toast check failed: page was closed or navigated. Expected: "${message}"`);
    }

    if (error instanceof Error && error.message.includes('waiting for')) {
      const allToasts = await toastMessage.allTextContents().catch(() => []);
      const errorMessage = allToasts.length === 0
        ? 'No toasts found on the page.'
        : `No matching toast found. Current toasts: ${JSON.stringify(allToasts)}`;
      throw new Error(`Toast with message "${message}" not found. ${errorMessage}`);
    }

    throw error;
  }
}

export { expect };
