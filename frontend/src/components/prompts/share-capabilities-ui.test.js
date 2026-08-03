import { createApp, nextTick } from "vue";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  state: {
    activeSettingsView: "shares-main",
    isSearchActive: false,
    req: { items: [], path: "/", source: "default", type: "directory" },
    selected: [],
    settings: {},
    sources: { info: { default: { readOnly: false } } },
    user: { locale: "en", permissions: { admin: false } },
  },
  closeTopPrompt: vi.fn(),
  hideTooltip: vi.fn(),
  showPrompt: vi.fn(),
  showTooltip: vi.fn(),
  createShare: vi.fn(),
  getSharesForPath: vi.fn(),
  listShares: vi.fn(),
  removeShare: vi.fn(),
  updateSharePath: vi.fn(),
  copyToClipboard: vi.fn(),
  emit: vi.fn(),
  on: vi.fn(),
  off: vi.fn(),
  showError: vi.fn(),
  showErrorToast: vi.fn(),
  showSuccessToast: vi.fn(),
}));

vi.mock("@/store", () => ({
  state: mocks.state,
  getters: {
    isFiles: vi.fn(() => true),
    isListing: vi.fn(() => true),
  },
  mutations: {
    closeTopPrompt: mocks.closeTopPrompt,
    hideTooltip: mocks.hideTooltip,
    showPrompt: mocks.showPrompt,
    showTooltip: mocks.showTooltip,
  },
}));

vi.mock("@/api", () => ({
  shareApi: {
    create: mocks.createShare,
    get: mocks.getSharesForPath,
    list: mocks.listShares,
    remove: mocks.removeShare,
    updatePath: mocks.updateSharePath,
  },
  usersApi: {},
}));

vi.mock("@/notify", () => ({
  notify: {
    showError: mocks.showError,
    showErrorToast: mocks.showErrorToast,
    showSuccessToast: mocks.showSuccessToast,
  },
}));

vi.mock("@/store/eventBus", () => ({
  eventBus: {
    emit: mocks.emit,
    on: mocks.on,
    off: mocks.off,
  },
}));

vi.mock("@/utils/clipboard", () => ({
  copyToClipboard: mocks.copyToClipboard,
}));

vi.mock("@/utils/constants", () => ({
  globalVars: {
    onlyOfficeUrl: "",
    userSelectableThemes: {},
  },
  tools: vi.fn(() => []),
}));

import Share from "./Share.vue";
import SidebarLinks from "./SidebarLinks.vue";
import ShareCapabilities from "@/components/share/Capabilities.vue";
import Shares from "@/views/settings/Shares.vue";

const CAPABILITY_KEYS = [
  "browse",
  "preview",
  "download",
  "thumbnail",
  "viewer",
  "create",
  "modify",
  "delete",
  "replace",
];

const ALL_FALSE = Object.fromEntries(CAPABILITY_KEYS.map((key) => [key, false]));
const ALL_TRUE = Object.fromEntries(CAPABILITY_KEYS.map((key) => [key, true]));
const CONFIGURED = {
  browse: true,
  preview: false,
  download: true,
  thumbnail: false,
  viewer: true,
  create: false,
  modify: true,
  delete: false,
  replace: true,
};
const DERIVED_CONFIGURED = {
  ...CONFIGURED,
  preview: true,
};
const EFFECTIVE = {
  browse: true,
  preview: false,
  download: false,
  thumbnail: false,
  viewer: true,
  create: false,
  modify: false,
  delete: false,
  replace: false,
};

const translate = (key) => key;
const mountedApps = [];

function mountComponent(component, props = {}) {
  const root = document.createElement("div");
  document.body.appendChild(root);
  const app = createApp(component, props);
  app.config.globalProperties.$t = translate;
  app.config.globalProperties.$route = { params: {}, path: "/", query: {} };
  app.config.globalProperties.$router = { push: vi.fn(), replace: vi.fn() };
  app.directive("focus", {});
  const vm = app.mount(root);
  mountedApps.push(app);
  return { root, vm };
}

async function flushComponentUpdates() {
  await Promise.resolve();
  await Promise.resolve();
  await nextTick();
}

function makeShare(overrides = {}) {
  return {
    hash: "share-hash",
    shareURL: "https://safe.example/public/share/share-hash",
    downloadURL: "https://safe.example/public/api/resources/share-hash",
    source: "default",
    path: "/docs/",
    shareType: "normal",
    expire: 0,
    status: "active",
    hasPassword: false,
    configuredCapabilities: { ...CONFIGURED },
    effectiveCapabilities: { ...EFFECTIVE },
    ...overrides,
  };
}

function bindMethods(component, context) {
  for (const [name, method] of Object.entries(component.methods ?? {})) {
    if (context[name] === undefined) {
      context[name] = method.bind(context);
    }
  }
  return context;
}

function shareContext(overrides = {}) {
  const context = {
    ...Share.data(),
    $t: translate,
    displayPath: "/docs/",
    displaySource: "default",
    hasExistingPassword: false,
    isEditMode: false,
    item: { isDir: true, name: "docs", path: "/docs/", source: "default" },
    link: {},
    sourceReadOnly: false,
    sort: vi.fn(),
    ...overrides,
  };
  return bindMethods(Share, context);
}

function sharesContext(overrides = {}) {
  return bindMethods(Shares, { $t: translate, ...overrides });
}

function capabilityState(items) {
  return Object.fromEntries(items.map((item) => [item.key, item.enabled]));
}

function expectNineExplicitBooleans(capabilities, expected) {
  expect(Object.keys(capabilities).sort()).toEqual([...CAPABILITY_KEYS].sort());
  expect(capabilities).toStrictEqual(expected);
  for (const key of CAPABILITY_KEYS) {
    expect(Object.hasOwn(capabilities, key)).toBe(true);
    expect(typeof capabilities[key]).toBe("boolean");
  }
}

beforeEach(() => {
  vi.clearAllMocks();
  mocks.state.user.permissions.admin = false;
  mocks.createShare.mockResolvedValue(makeShare());
  mocks.copyToClipboard.mockResolvedValue(true);
  mocks.getSharesForPath.mockResolvedValue([]);
  mocks.listShares.mockResolvedValue([]);
});

afterEach(() => {
  while (mountedApps.length > 0) {
    mountedApps.pop().unmount();
  }
  document.body.innerHTML = "";
});

describe("Share configured capability form state", () => {
  it("renders Browse and Preview as derived controls while other normal Share controls remain editable", async () => {
    const { root, vm } = mountComponent(Share, {
      item: { isDir: true, name: "docs", path: "/docs/", source: "default" },
    });
    await flushComponentUpdates();

    const expected = {
      browse: true,
      preview: true,
      download: true,
      thumbnail: true,
      viewer: true,
      create: false,
      modify: false,
      delete: false,
      replace: false,
    };
    const invertedControls = new Set(["download", "thumbnail", "viewer"]);
    const derivedControls = new Set(["browse", "preview"]);
    for (const key of CAPABILITY_KEYS) {
      const input = root.querySelector(`input[aria-label="${key}"]`);
      expect(input, `missing configured capability control: ${key}`).not.toBeNull();
      const configuredValue = invertedControls.has(key) ? !input.checked : input.checked;
      expect(configuredValue, `configured capability state: ${key}`).toBe(expected[key]);
      expect(input.disabled, `configured capability editability: ${key}`).toBe(derivedControls.has(key));
    }

    const browseHelp = root.querySelector('input[aria-label="browse"]')
      .closest(".toggle-container")
      .querySelector(".tooltip-info-icon");
    browseHelp.dispatchEvent(new MouseEvent("mouseenter", { clientX: 10, clientY: 20 }));
    expect(mocks.showTooltip).toHaveBeenLastCalledWith({
      content: "settings.permissions.browse = share.shareType",
      x: 10,
      y: 20,
    });

    const previewHelp = root.querySelector('input[aria-label="preview"]')
      .closest(".toggle-container")
      .querySelector(".tooltip-info-icon");
    previewHelp.dispatchEvent(new MouseEvent("mouseenter", { clientX: 30, clientY: 40 }));
    expect(mocks.showTooltip).toHaveBeenLastCalledWith({
      content: "settings.permissions.preview = profileSettings.showThumbnails / profileSettings.fileViewerOptions",
      x: 30,
      y: 40,
    });

    const createInput = root.querySelector('input[aria-label="create"]');
    createInput.checked = true;
    createInput.dispatchEvent(new Event("change", { bubbles: true }));
    await nextTick();
    expect(vm.configuredCapabilities.create).toBe(true);
  });

  it("does not accept direct Browse/Preview edits and derives Preview from Thumbnail/Viewer", () => {
    const context = shareContext({
      configuredCapabilities: { ...ALL_FALSE },
      shareType: "normal",
    });

    context.setConfiguredCapability("browse", false);
    context.setConfiguredCapability("preview", true);
    expect(context.configuredCapabilities).toMatchObject({ browse: true, preview: false });

    context.setConfiguredCapability("thumbnail", true);
    expect(context.configuredCapabilities).toMatchObject({ thumbnail: true, preview: true });

    context.setConfiguredCapability("thumbnail", false);
    context.setConfiguredCapability("viewer", true);
    expect(context.configuredCapabilities).toMatchObject({ viewer: true, preview: true });

    context.setConfiguredCapability("viewer", false);
    expect(context.configuredCapabilities.preview).toBe(false);
  });

  it("keeps all seven non-derived normal Share capabilities configurable", () => {
    const context = shareContext({
      configuredCapabilities: { ...ALL_FALSE },
      shareType: "normal",
    });
    const configurable = ["download", "thumbnail", "viewer", "create", "modify", "delete", "replace"];

    for (const capability of configurable) {
      context.setConfiguredCapability(capability, true);
      expect(context.configuredCapabilities[capability], capability).toBe(true);
    }
    expect(context.configuredCapabilities).toMatchObject({ browse: true, preview: true });

    for (const capability of configurable) {
      context.setConfiguredCapability(capability, false);
      expect(context.configuredCapabilities[capability], capability).toBe(false);
    }
    expect(context.configuredCapabilities).toMatchObject({ browse: true, preview: false });
  });

  it("locks Upload Create on and disables capabilities the backend derives", async () => {
    const { root, vm } = mountComponent(Share, {
      item: { isDir: true, name: "docs", path: "/docs/", source: "default" },
    });
    await flushComponentUpdates();

    const shareType = root.querySelector('option[value="upload"]').closest("select");
    shareType.value = "upload";
    shareType.dispatchEvent(new Event("change", { bubbles: true }));
    await nextTick();

    const previewHelp = root.querySelector('input[aria-label="preview"]')
      .closest(".toggle-container")
      .querySelector(".tooltip-info-icon");
    previewHelp.dispatchEvent(new MouseEvent("mouseenter", { clientX: 50, clientY: 60 }));
    expect(mocks.showTooltip).toHaveBeenLastCalledWith({
      content: "settings.permissions.preview = share.shareType",
      x: 50,
      y: 60,
    });

    expectNineExplicitBooleans(vm.configuredCapabilities, {
      browse: false,
      preview: false,
      download: true,
      thumbnail: true,
      viewer: true,
      create: true,
      modify: false,
      delete: false,
      replace: false,
    });
    for (const key of ["browse", "preview", "create"]) {
      expect(root.querySelector(`input[aria-label="${key}"]`).disabled, key).toBe(true);
    }
    for (const key of ["download", "thumbnail", "viewer", "modify", "delete", "replace"]) {
      expect(root.querySelector(`input[aria-label="${key}"]`).disabled, key).toBe(false);
    }

    vm.setConfiguredCapability("create", false);
    expect(vm.configuredCapabilities.create).toBe(true);

    shareType.value = "normal";
    shareType.dispatchEvent(new Event("change", { bubbles: true }));
    await nextTick();
    expectNineExplicitBooleans(vm.configuredCapabilities, {
      browse: true,
      preview: true,
      download: true,
      thumbnail: true,
      viewer: true,
      create: false,
      modify: false,
      delete: false,
      replace: false,
    });
  });

  it("hydrates all nine configured capabilities in the management edit watcher", () => {
    const link = makeShare();
    const context = shareContext({ isEditMode: true, link });

    Share.watch.isEditMode.handler.call(context, true);

    expectNineExplicitBooleans(context.configuredCapabilities, DERIVED_CONFIGURED);
    expect(context.configuredCapabilities).not.toBe(link.configuredCapabilities);
  });

  it("hydrates all nine configured capabilities when editing from the path share list", () => {
    const link = makeShare();
    const context = shareContext();

    Share.methods.editLink.call(context, link);

    expectNineExplicitBooleans(context.configuredCapabilities, DERIVED_CONFIGURED);
    expect(context.configuredCapabilities).not.toBe(link.configuredCapabilities);
  });

  it("submits all nine explicit booleans with normal Share derived values", async () => {
    const context = shareContext({
      configuredCapabilities: { ...ALL_FALSE },
      listing: false,
      shareType: "normal",
    });

    await Share.methods.submit.call(context);

    const payload = mocks.createShare.mock.calls[0][0];
    expectNineExplicitBooleans(payload.configuredCapabilities, { ...ALL_FALSE, browse: true });
  });

  it("submits Upload Browse/Preview false and Create true even from contradictory form state", async () => {
    const context = shareContext({
      configuredCapabilities: { ...ALL_TRUE, create: false },
      listing: false,
      shareType: "upload",
    });

    await Share.methods.submit.call(context);

    const payload = mocks.createShare.mock.calls[0][0];
    expectNineExplicitBooleans(payload.configuredCapabilities, {
      ...ALL_TRUE,
      browse: false,
      preview: false,
      create: true,
    });
  });
});

describe("effective Share capability presentation", () => {
  it("renders effective values and an explicit configured-capability reduction notice", () => {
    const { root } = mountComponent(ShareCapabilities, {
      capabilities: { ...ALL_FALSE, browse: true },
      configuredCapabilities: { ...ALL_TRUE },
    });

    expect(root.querySelector('[data-capability="browse"]').dataset.enabled).toBe("true");
    expect(root.querySelector('[data-capability="download"]').dataset.enabled).toBe("false");
    expect(root.querySelector('[data-capability="download"] .capability-warning')).not.toBeNull();
    expect(root.querySelector(".capability-reduction-notice").textContent).toContain(
      "owner's current permissions or the Share security snapshot",
    );
  });

  it("renders management-list operations from effective capabilities", async () => {
    mocks.listShares.mockResolvedValue([
      makeShare({
        configuredCapabilities: { ...ALL_TRUE },
        effectiveCapabilities: { ...ALL_FALSE, browse: true },
      }),
    ]);
    const { root } = mountComponent(Shares);
    await flushComponentUpdates();

    expect(root.querySelector('[data-capability="download"]').dataset.enabled).toBe("false");
    expect(root.querySelector('button[aria-label="buttons.copyDownloadLinkToClipboard"]').disabled).toBe(true);
    expect(root.querySelector('button[aria-label="buttons.copyToClipboard"]').disabled).toBe(false);
  });

  for (const [name, component] of [["path list", Share], ["management list", Shares]]) {
    it(`${name} uses only effective capabilities and detects reductions`, () => {
      const share = makeShare({
        configuredCapabilities: { ...ALL_TRUE },
        effectiveCapabilities: { ...ALL_FALSE, browse: true, viewer: true },
      });
      const context = component === Share ? shareContext() : sharesContext();

      const items = component.methods.effectiveCapabilityItems.call(context, share);

      expectNineExplicitBooleans(capabilityState(items), {
        ...ALL_FALSE,
        browse: true,
        viewer: true,
      });
      expect(component.methods.hasCapabilityReduction.call(context, share)).toBe(true);
    });
  }

  it("does not treat configured true as effectively available", () => {
    const share = makeShare({
      configuredCapabilities: { ...ALL_FALSE, download: true },
      effectiveCapabilities: { ...ALL_FALSE, download: false },
    });
    const context = sharesContext();

    const items = Shares.methods.effectiveCapabilityItems.call(context, share);

    expect(capabilityState(items).download).toBe(false);
    expect(Shares.methods.hasCapabilityReduction.call(context, share)).toBe(true);
  });

  it("does not expand effective capabilities for an administrator owner", () => {
    mocks.state.user.permissions.admin = true;
    const share = makeShare({
      configuredCapabilities: { ...ALL_TRUE },
      effectiveCapabilities: { ...ALL_FALSE },
    });
    const context = sharesContext({ user: mocks.state.user });

    const items = Shares.methods.effectiveCapabilityItems.call(context, share);

    expectNineExplicitBooleans(capabilityState(items), ALL_FALSE);
  });

  it("keeps file Share write capabilities disabled when the backend returns false", () => {
    const share = makeShare({
      shareType: "normal",
      configuredCapabilities: { ...ALL_TRUE },
      effectiveCapabilities: { ...ALL_TRUE, create: false, modify: false, delete: false, replace: false },
    });

    const state = capabilityState(Shares.methods.effectiveCapabilityItems.call(sharesContext(), share));

    expect(state).toMatchObject({ create: false, modify: false, delete: false, replace: false });
  });

  it("keeps upload Share read capabilities disabled when the backend returns false", () => {
    const share = makeShare({
      shareType: "upload",
      configuredCapabilities: { ...ALL_TRUE },
      effectiveCapabilities: {
        ...ALL_TRUE,
        browse: false,
        preview: false,
        download: false,
        thumbnail: false,
        viewer: false,
      },
    });

    const state = capabilityState(Shares.methods.effectiveCapabilityItems.call(sharesContext(), share));

    expect(state).toMatchObject({
      browse: false,
      preview: false,
      download: false,
      thumbnail: false,
      viewer: false,
    });
  });
});

describe("Share password management", () => {
  it("uses hasPassword without expecting a password value", () => {
    expect(Share.computed.hasExistingPassword.call({
      editingLink: null,
      isEditMode: true,
      link: makeShare({ hasPassword: true }),
    })).toBe(true);
    expect(Shares.methods.isPasswordProtected(makeShare({ hasPassword: true }))).toBe(true);
    expect(Shares.methods.isPasswordProtected(makeShare({ hasPassword: false }))).toBe(false);
  });

  it("does not clear an existing password when replacement mode is left blank", async () => {
    const link = makeShare({ hasPassword: true });
    const context = shareContext({
      configuredCapabilities: { ...CONFIGURED },
      hasExistingPassword: true,
      isChangingPassword: true,
      isEditMode: true,
      link,
      password: "",
      removePassword: false,
    });

    await Share.methods.submit.call(context);

    expect(mocks.createShare.mock.calls[0][0]).not.toHaveProperty("password");
  });

  it("removes an existing password only after an explicit removal action", async () => {
    const link = makeShare({ hasPassword: true });
    const context = shareContext({
      configuredCapabilities: { ...CONFIGURED },
      hasExistingPassword: true,
      isEditMode: true,
      link,
      password: "",
      removePassword: false,
    });

    Share.methods.markPasswordForRemoval.call(context);
    await Share.methods.submit.call(context);

    expect(mocks.createShare.mock.calls[0][0]).toHaveProperty("password", "");
  });
});

describe("Share management DTO boundaries", () => {
  it("does not add a createdAt column", () => {
    const columns = Shares.computed.sharesTableColumns.call({ $t: translate });
    const keys = columns.map(({ key }) => key);

    expect(keys).not.toContain("createdAt");
    expect(keys.some((key) => /capabilit/i.test(key))).toBe(true);
    expect(keys.some((key) => /password/i.test(key))).toBe(true);
  });

  it("does not access secret or absent management DTO fields", async () => {
    const accessed = [];
    const forbidden = new Set(["token", "accessToken", "password", "password_hash", "createdAt"]);
    const share = new Proxy(makeShare(), {
      get(target, property, receiver) {
        if (forbidden.has(property)) {
          accessed.push(property);
          throw new Error(`forbidden DTO field read: ${String(property)}`);
        }
        return Reflect.get(target, property, receiver);
      },
    });
    mocks.listShares.mockResolvedValue([share]);
    const context = sharesContext({ error: null, links: [], loading: false });

    await Shares.methods.reloadShares.call(context);
    Shares.methods.effectiveCapabilityItems.call(context, share);
    Shares.methods.hasCapabilityReduction.call(context, share);
    Shares.methods.isPasswordProtected(share);

    expect(accessed).toEqual([]);
    expect(context.links).toEqual([share]);
  });

  it("copies only backend-provided shareURL and downloadURL values", async () => {
    const share = makeShare();

    await Share.methods.copyShareURL.call(shareContext(), share);
    await Share.methods.copyDownloadURL.call(shareContext(), share);
    await Shares.methods.copyShareURL.call(sharesContext(), share);
    await Shares.methods.copyDownloadURL.call(sharesContext(), share);

    expect(mocks.copyToClipboard.mock.calls).toEqual([
      [share.shareURL],
      [share.downloadURL],
      [share.shareURL],
      [share.downloadURL],
    ]);
  });

  it("uses the backend shareURL as the base for sidebar Share links", () => {
    const share = makeShare({
      shareURL: "https://safe.example/proxy/public/share/share-hash?signature=backend",
    });
    const context = bindMethods(SidebarLinks, {
      ...SidebarLinks.data(),
      availableShares: [share],
      isSelectingPath: true,
      newLink: { category: "share", target: share.shareURL },
      tempSelectedPath: "/reports/quarterly",
    });

    expect(context.getShareHash(share.shareURL)).toBe(share.hash);
    expect(context.getShareSubpath(share.shareURL)).toBe("/");
    context.confirmPathSelection();

    expect(context.newLink.target).toBe(
      "https://safe.example/proxy/public/share/share-hash/reports/quarterly?signature=backend",
    );
    expect(context.getShareSubpath(context.newLink.target)).toBe("/reports/quarterly");
  });
});
