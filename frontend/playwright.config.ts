import { defineConfig, devices } from "@playwright/test";

/**
 * Read environment variables from file.
 * https://github.com/motdotla/dotenv
 */
// require('dotenv').config();

/**
 * See https://playwright.dev/docs/test-configuration.
 */
const sharedHostAcceptance = Boolean(process.env.FILEBROWSER_ACCEPTANCE_URL);
if (sharedHostAcceptance && !process.env.FILEBROWSER_ACCEPTANCE_URL?.startsWith("https://")) {
  throw new Error("Shared-host acceptance requires verified HTTPS");
}

export default defineConfig({
  globalSetup: sharedHostAcceptance ? undefined : "./tests/playwright/screenshots-setup.ts",
  timeout: sharedHostAcceptance ? 60000 : 5000,
  testDir: sharedHostAcceptance ? "./tests/playwright/shared-host" : "./tests/playwright/screenshots",
  outputDir: sharedHostAcceptance ? process.env.FILEBROWSER_ACCEPTANCE_OUTPUT : undefined,
  /* Run tests in files in parallel */
  fullyParallel: false,
  /* Fail the build on CI if you accidentally left test.only in the source code. */
  forbidOnly: false,
  /* Retry on CI only */
  retries: 2,
  /* Opt out of parallel tests on CI. */
  /* Reporter to use. See https://playwright.dev/docs/test-reporters */
  reporter: "line",
  /* Shared settings for all the projects below. See https://playwright.dev/docs/api/class-testoptions. */
  use: {
    actionTimeout: 5000,
    storageState: sharedHostAcceptance ? undefined : "loginAuth.json",
    /* Base URL to use in actions like `await page.goto('/')`. */
    baseURL: sharedHostAcceptance ? process.env.FILEBROWSER_ACCEPTANCE_URL : "http://localhost:8080",
    ignoreHTTPSErrors: false,

    /* Collect trace when retrying the failed test. See https://playwright.dev/docs/trace-viewer */
    trace: sharedHostAcceptance ? "off" : "on-first-retry",

    /* Set default locale to English (US) */
    locale: "en-US",
  },

  /* Configure projects for major browsers */
  projects: sharedHostAcceptance ? [{
    name: "shared-host",
    use: { ...devices["Desktop Chrome"] },
    retries: 0,
  }] : [
    {
      name: "dark-screenshots",
      use: {
        ...devices["Desktop Chrome"],
        theme: 'dark',
      },
      /* Include every spec under testDir (prompts.spec.ts, settings-screenshots, etc.) */
      testMatch: /\.spec\.ts$/,
      retries: 0,
    },
    {
      name: "light-screenshots",
      use: {
        ...devices["Desktop Chrome"],
        theme: 'light',
      },
      testMatch: /\.spec\.ts$/,
      retries: 0,
    },
  ],
});
