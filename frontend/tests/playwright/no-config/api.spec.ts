import { expect, test } from "../test-setup";

test("verify scoped user can't access files outside of their scope", async ({ page }) => {
    // set basic auth credentials for protected /subpath route
    await page.setExtraHTTPHeaders({
        'Authorization': `Basic ZGVtby0xMjcuMC4wLjE6U2VjdXJlUGFzczEyMyE=`
    });

    // Traversal is rejected by path validation before filesystem access.
    const response = await page.goto("/api/resources?path=../&source=backend", { waitUntil: 'networkidle' });
    expect(response?.status()).toBe(400);
    const responseBody = await response?.json();
    expect(responseBody).toEqual({ status: 400, message: "invalid resource path: path traversal is not allowed" });
    expect(responseBody).not.toHaveProperty('content');
    expect(responseBody).not.toHaveProperty('files');
});
