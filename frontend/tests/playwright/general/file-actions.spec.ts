import { checkForNotification, expect, test } from "../test-setup";

const copyDestLabel = (page: import("@playwright/test").Page) =>
  page.locator('div[aria-label="copy-prompt"] .move-copy-path-picker');

/** Matches `_docker/src/general/backend/server-config.yaml` source name. */
const GENERAL_COPY_SOURCE = "playwright + files";

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
  await expect(page.locator('#result-list')).toHaveCount(1);
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
  await expect(page.locator('#result-list')).toHaveCount(1);
  await page.locator('li[aria-label="file.tar.gz"]').click();
  await expect(page).toHaveTitle("Graham's Filebrowser - Files - file.tar.gz");
  await expect(page.locator('#previewer')).toContainText('Preview is not available for this file.');
  checkForErrors();
})

test("open nested file in /files dir from search", async({ page, checkForErrors }) => {
  await page.goto("/files/");
  await expect(page).toHaveTitle("Graham's Filebrowser - Files - playwright-files");
  await page.locator('#search-bar-input').click()
  await page.locator('#search-input').fill('binary');
  await expect(page.locator('#result-list')).toHaveCount(1);
  await page.locator('li[aria-label="binary.dat"]').click();
  await expect(page).toHaveTitle("Graham's Filebrowser - Files - binary.dat");
  await expect(page.locator('#previewer')).toContainText('Preview is not available for this file.');
  checkForErrors();
})

test("open markdown file from search", async({ page, checkForErrors }) => {
  await page.goto("/files/");
  await expect(page).toHaveTitle("Graham's Filebrowser - Files - playwright-files");
  await page.locator('#search-bar-input').click()
  await page.locator('#search-input').fill('for testing');
  await expect(page.locator('#result-list')).toHaveCount(1);
  await page.locator('li[aria-label="for testing.md"]').click();
  await expect(page).toHaveTitle("Graham's Filebrowser - Files - for testing.md");
  await expect(page.locator('#markedown-viewer')).toContainText('this is a test');
  checkForErrors();
})

test("2x copy from listing to new folder", async({ page, checkForErrors }) => {
  await page.goto("/files/");
  await expect(page).toHaveTitle("Graham's Filebrowser - Files - playwright-files");
  await page.locator('a[aria-label="copyme.txt"]').waitFor({ state: 'visible' });
  await page.locator('a[aria-label="copyme.txt"]').click( { button: "right" });
  await page.locator('.selected-count-header').waitFor({ state: 'visible' });
  await expect(page.locator('.selected-count-header')).toHaveText('1');
  await page.locator('button[aria-label="Copy file"]').click();
  await expect(copyDestLabel(page)).toHaveText(`/ (${GENERAL_COPY_SOURCE})`);
  await expect(page.locator('div[aria-label="copy-prompt"] .listing-item[aria-selected="true"]')).toHaveCount(0);
  await page.locator('div[aria-label="copy-prompt"] .listing-item[aria-label="myfolder"]').click();
  await expect(page.locator('div[aria-label="copy-prompt"] .listing-item[aria-selected="true"]')).toHaveCount(1);
  await page.locator('button[aria-label="Copy"]').click();
  await checkForNotification(page, "Files copied successfully!");
  await page.goto("/files/playwright%20%2B%20files/myfolder/");
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
  await expect(copyDestLabel(page)).toHaveText(`/myfolder/ (${GENERAL_COPY_SOURCE})`);
  await page.locator('div[aria-label="copy-prompt"] .listing-item[aria-label="newfolder"]').click();
  await page.locator('button[aria-label="Copy"]').click();
  await checkForNotification(page, "Files copied successfully!");
  await page.goto("/files/playwright%20%2B%20files/myfolder/newfolder/");
  await expect(page).toHaveTitle(/.* - newfolder/);
  checkForErrors();
})

test("copy 'text-files' to 'folder#hash' verify folder size is updated", async({ page, checkForErrors }) => {
  await page.goto("/files/");
  await expect(page).toHaveTitle("Graham's Filebrowser - Files - playwright-files");
  
  // Find folder#hash and get its size before copy
  await page.locator('a[aria-label="folder#hash"]').waitFor({ state: 'visible' });
  const folderHashLink = page.locator('a[aria-label="folder#hash"]');
  const textFilesLink = page.locator('a[aria-label="text-files"]');
  const textFilesSizeBefore = await textFilesLink.locator('.size').textContent();
  const folderHashSizeBefore = await folderHashLink.locator('.size').textContent();
  
  // Copy myfotext-filesder
  await textFilesLink.click({ button: "right" });
  await page.locator('.selected-count-header').waitFor({ state: 'visible' });
  await expect(page.locator('.selected-count-header')).toHaveText('1');
  await page.locator('button[aria-label="Copy file"]').click();
  await expect(copyDestLabel(page)).toHaveText(`/ (${GENERAL_COPY_SOURCE})`);
  await page.locator('div[aria-label="copy-prompt"] .listing-item[aria-label="folder#hash"]').click();
  await page.locator('button[aria-label="Copy"]').click();
  await checkForNotification(page, "Files copied successfully!");
  await page.locator('.notification-buttons .button').waitFor({ state: 'visible' });
  await page.locator('.notification-buttons .button').click();

  // verify folder size is updated
  const folderSizeAfter = await textFilesLink.locator('.size').textContent();
  expect(folderSizeAfter).not.toBe("0.0 bytes");
  expect(folderSizeAfter).toBe(textFilesSizeBefore);

  // Go back to root and verify the copied folder has a non-zero size
  await page.goto("/files/");
  await page.locator('a[aria-label="folder#hash"]').waitFor({ state: 'visible' });
  const copiedFolderSize = await page.locator('a[aria-label="folder#hash"]').locator('.size').textContent();
  expect(copiedFolderSize).not.toBe("0.0 bytes");
  expect(copiedFolderSize).not.toBe(folderHashSizeBefore);
  checkForErrors();
})

test("delete file moves to recycle bin and restores without overwriting", async({ page, checkForErrors }) => {
  await page.goto("/files/");
  await expect(page).toHaveTitle("Graham's Filebrowser - Files - playwright-files");
  await page.locator('a[aria-label="deleteme.txt"]').waitFor({ state: 'visible' });
  await page.locator('a[aria-label="deleteme.txt"]').click({ button: "right" });
  await page.locator('.selected-count-header').waitFor({ state: 'visible' });
  await expect(page.locator('.selected-count-header')).toHaveText('1');
  await page.locator('button[aria-label="Delete"]').click();
  await expect( page.locator('.card-content')).toContainText('/deleteme.txt');
  const trashResponse = page.waitForResponse(response => response.request().method() === 'POST' && new URL(response.url()).pathname.endsWith('/api/trash'));
  await page.locator('button[aria-label="Confirm-Delete"]').click();
  await checkForNotification(page, "In recycle bin");
  const moved = await (await trashResponse).json();
  expect(moved.state).toBe('trashed');
  await expect(page.locator('a[aria-label="deleteme.txt"]')).toHaveCount(0);

  // Seed a different occupant through the normal authenticated upload API.
  const occupant = await page.request.post(`/api/resources?${new URLSearchParams({ source: moved.source, path: '/deleteme.txt' })}`, { data: 'new synthetic occupant' });
  expect(occupant.status()).toBe(200);
  await page.getByRole('link', { name: 'Recycle bin', exact: true }).click();
  const row = page.getByRole('row').filter({ hasText: moved.operation_id });
  await expect(row).toContainText('In recycle bin');
  await row.getByRole('button', { name: 'Restore', exact: true }).click();
  const form = page.locator('.trash-restore');
  const conflictResponse = page.waitForResponse(response => response.request().method() === 'POST' && new URL(response.url()).pathname.endsWith('/restore'));
  await form.getByRole('button', { name: 'Confirm', exact: true }).click();
  expect((await conflictResponse).status()).toBe(409);
  await expect(page.locator('.trash-message')).toContainText('destination already exists');
  await form.getByRole('button', { name: 'Check operation', exact: true }).click();
  await expect(form).toHaveCount(0);
  await row.getByRole('button', { name: 'Restore', exact: true }).click();
  await page.getByLabel('Destination path including file name').fill('/restored-deleteme.txt');
  await page.locator('.trash-restore').getByRole('button', { name: 'Confirm', exact: true }).click();
  await expect(row).toContainText('Restored');
  const restored = await page.request.get(`/api/resources?${new URLSearchParams({ source: moved.source, path: '/restored-deleteme.txt', checksum: 'sha256' })}`);
  expect(restored.status()).toBe(200);
  expect((await restored.json()).checksums.sha256).toBe(moved.sha256);
  const protectedOccupant = await page.request.get(`/api/resources?${new URLSearchParams({ source: moved.source, path: '/deleteme.txt', content: 'true' })}`);
  expect((await protectedOccupant.json()).content).toBe('new synthetic occupant');
  // The deliberately rejected restore produces exactly one browser/API 409.
  checkForErrors(1, 1);
})

test("directory delete is explicitly refused without permanent deletion", async({ page, checkForErrors }) => {
  await page.goto('/files/');
  await page.locator('a[aria-label="folder#hash"]').click({ button: 'right' });
  await page.locator('button[aria-label="Delete"]').click();
  const mutations: string[] = [];
  page.on('request', request => { if (request.method() === 'DELETE' || (request.method() === 'POST' && new URL(request.url()).pathname.endsWith('/api/trash'))) mutations.push(request.method()); });
  await page.locator('button[aria-label="Confirm-Delete"]').click();
  await expect(page.locator('.error-banner')).toContainText('Directories and symlinks cannot be moved');
  expect(mutations).toEqual([]);
  await page.getByRole('button', { name: 'Cancel', exact: true }).click();
  await expect(page.locator('a[aria-label="folder#hash"]')).toBeVisible();
  checkForErrors();
})

test("delete nested file prompt", async({ page, checkForErrors }) => {
  await page.goto("/files/playwright%20%2B%20files/folder%23hash/");
  await expect(page).toHaveTitle("Graham's Filebrowser - Files - folder#hash");
  await page.locator('a[aria-label="file#.sh"]').waitFor({ state: 'visible' });
  await page.locator('a[aria-label="file#.sh"]').click({ button: "right" });
  await page.locator('.selected-count-header').waitFor({ state: 'visible' });
  await expect(page.locator('.selected-count-header')).toHaveText('1');
  await page.locator('button[aria-label="Delete"]').click();
  await expect(page.locator('.card-content')).toContainText('/folder#hash/file#.sh');
  checkForErrors();
})
