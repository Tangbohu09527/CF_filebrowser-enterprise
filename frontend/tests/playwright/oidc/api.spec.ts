import { expect, test } from "../test-setup";

test("verify scoped user can't access files outside of their scope", async ({ page }) => {
    // set basic auth credentials for protected /subpath route
    await page.setExtraHTTPHeaders({
        'Authorization': `Basic ZGVtby0xMjcuMC4wLjE6U2VjdXJlUGFzczEyMyE=`
    });

    // Traversal is rejected by path validation before filesystem access.
    const response = await page.goto("/api/resources?path=../../etc/passwd&source=playwright-files", { waitUntil: 'networkidle' });
    
    // Check the JSON response body
    const responseBody = await response?.json();
    expect(responseBody).toEqual({ status: 400, message: "invalid resource path: path traversal is not allowed" });
    expect(response?.status()).toBe(400);
    expect(responseBody).not.toHaveProperty('content');
    expect(responseBody).not.toHaveProperty('files');

});

test("verify scoped user can't access files outside their scope", async ({ page }) => {
    // set basic auth credentials for protected /subpath route
    await page.setExtraHTTPHeaders({
        'Authorization': `Basic ZGVtby0xMjcuMC4wLjE6U2VjdXJlUGFzczEyMyE=`
    });

    // A parent-directory request must be rejected, without a resource listing.
    const response = await page.goto("/api/resources?path=../&source=playwright-files", { waitUntil: 'networkidle' });
    
    // Check the JSON response body
    const responseBody = await response?.json();
    expect(responseBody).toEqual({ status: 400, message: "invalid resource path: path traversal is not allowed" });
    expect(response?.status()).toBe(400);
    expect(responseBody).not.toHaveProperty('content');
    expect(responseBody).not.toHaveProperty('files');

});
