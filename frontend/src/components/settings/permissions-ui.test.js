import { createApp, nextTick } from "vue";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  closeTopPrompt: vi.fn(),
  setLoading: vi.fn(),
  showTooltip: vi.fn(),
  hideTooltip: vi.fn(),
  updatePromptTitle: vi.fn(),
  showPrompt: vi.fn(),
  createUser: vi.fn(),
  getUser: vi.fn(),
  updateUser: vi.fn(),
  getSetting: vi.fn(),
  emit: vi.fn(),
  on: vi.fn(),
  off: vi.fn(),
  showError: vi.fn(),
  showSuccessToast: vi.fn(),
}));

vi.mock("@/store", () => ({
  state: {
    settings: {},
    user: {
      loginMethod: "password",
      permissions: { admin: true },
    },
  },
  mutations: {
    closeTopPrompt: mocks.closeTopPrompt,
    hideTooltip: mocks.hideTooltip,
    setLoading: mocks.setLoading,
    showPrompt: mocks.showPrompt,
    showTooltip: mocks.showTooltip,
    updatePromptTitle: mocks.updatePromptTitle,
  },
}));

vi.mock("@/api", () => ({
  authApi: {},
  settingsApi: { get: mocks.getSetting },
  usersApi: {
    create: mocks.createUser,
    get: mocks.getUser,
    update: mocks.updateUser,
  },
}));

vi.mock("@/notify", () => ({
  notify: {
    showError: mocks.showError,
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

vi.mock("@/utils/constants", () => ({
  globalVars: {
    jwtAvailable: false,
    ldapAvailable: false,
    oidcAvailable: false,
    passwordAvailable: true,
    proxyAvailable: false,
  },
}));

import Permissions from "./Permissions.vue";
import UserEdit from "@/components/prompts/UserEdit.vue";

const translations = {
  "settings.permissions.admin": "Administrator",
  "settings.permissions.api": "API",
  "settings.permissions.browse": "Browse",
  "settings.permissions.create": "Create",
  "settings.permissions.delete": "Delete",
  "settings.permissions.download": "Download",
  "settings.permissions.modify": "Modify",
  "settings.permissions.preview": "Preview",
  "settings.permissions.realtime": "Realtime",
  "settings.permissions.share": "Share",
  "settings.permissions.browseDescription": "View directories and file lists",
  "settings.permissions.previewDescription": "Preview file contents in the browser",
  "settings.permissions.downloadDescription": "Download original files",
};

const translate = (key) => translations[key] ?? key;
const mountedApps = [];

function mountPermissions(permissions) {
  for (const key of ["api", "create", "delete", "modify", "realtime", "share"]) {
    permissions[key] ??= false;
  }
  const root = document.createElement("div");
  document.body.appendChild(root);
  const app = createApp(Permissions, { permissions });
  app.config.globalProperties.$t = translate;
  app.mount(root);
  mountedApps.push(app);
  return root;
}

function checkbox(root, name) {
  return root.querySelector(`input[aria-label="${name}"]`);
}

async function setChecked(input, checked) {
  input.checked = checked;
  input.dispatchEvent(new Event("change", { bubbles: true }));
  await nextTick();
}

function formContext({ isNew, user, userId }) {
  return {
    ...UserEdit.data(),
    $t: translate,
    firstAvailableLoginMethod: "password",
    globalVars: {
      jwtAvailable: false,
      ldapAvailable: false,
      oidcAvailable: false,
      passwordAvailable: true,
      proxyAvailable: false,
    },
    isNew,
    selectedSources: [],
    updatePromptTitle: vi.fn(),
    user,
    userId,
  };
}

afterEach(() => {
  while (mountedApps.length > 0) {
    mountedApps.pop().unmount();
  }
  document.body.innerHTML = "";
});

beforeEach(() => {
  vi.clearAllMocks();
});

describe("Browse, Preview, and Download permission controls", () => {
  it("renders all three controls with concise descriptions", () => {
    const root = mountPermissions({
      admin: false,
      browse: false,
      preview: true,
      download: false,
    });

    expect(checkbox(root, "Browse")).not.toBeNull();
    expect(checkbox(root, "Preview")).not.toBeNull();
    expect(checkbox(root, "Download")).not.toBeNull();

    const descriptions = [...root.querySelectorAll(".tooltip-info-icon")].map((icon) => {
      icon.dispatchEvent(new MouseEvent("mouseenter", { bubbles: true }));
      return mocks.showTooltip.mock.calls.at(-1)?.[0]?.content;
    });
    expect(descriptions).toEqual(expect.arrayContaining([
      "View directories and file lists",
      "Preview file contents in the browser",
      "Download original files",
    ]));
  });

  it("keeps Browse, Preview, and Download independent", async () => {
    const permissions = {
      admin: false,
      browse: false,
      preview: true,
      download: false,
    };
    const root = mountPermissions(permissions);

    await setChecked(checkbox(root, "Browse"), true);
    expect(permissions).toMatchObject({ browse: true, preview: true, download: false });

    await setChecked(checkbox(root, "Preview"), false);
    expect(permissions).toMatchObject({ browse: true, preview: false, download: false });

    await setChecked(checkbox(root, "Download"), true);
    expect(permissions).toMatchObject({ browse: true, preview: false, download: true });
  });

  it("does not overwrite read permissions when Admin changes", async () => {
    const permissions = {
      admin: false,
      browse: false,
      preview: true,
      download: false,
    };
    const root = mountPermissions(permissions);

    await setChecked(checkbox(root, "Administrator"), true);

    expect(permissions).toMatchObject({
      admin: true,
      browse: false,
      preview: true,
      download: false,
    });
  });
});

describe("user permission form data", () => {
  it("uses userDefaults without inventing read permission values", async () => {
    const defaults = {
      loginMethod: "password",
      permissions: { browse: false, preview: true, download: false },
      scopes: [],
      username: "",
    };
    mocks.getSetting.mockResolvedValue(structuredClone(defaults));
    const context = formContext({ isNew: true, user: UserEdit.data().user });

    await UserEdit.methods.fetchData.call(context);

    expect(mocks.getSetting).toHaveBeenCalledWith("userDefaults");
    expect(context.user.permissions).toEqual(defaults.permissions);
  });

  it("reflects all three permissions returned for an existing user", async () => {
    mocks.getUser.mockResolvedValue({
      id: 42,
      loginMethod: "password",
      permissions: { browse: true, preview: false, download: true },
      scopes: [],
      username: "reader",
    });
    const context = formContext({ isNew: false, user: UserEdit.data().user, userId: 42 });

    await UserEdit.methods.fetchData.call(context);

    expect(mocks.getUser).toHaveBeenCalledWith(42);
    expect(context.user.permissions).toEqual({
      browse: true,
      preview: false,
      download: true,
    });
  });

  it("passes explicit false values to user creation", async () => {
    const context = formContext({
      isNew: true,
      user: {
        loginMethod: "password",
        permissions: { browse: false, preview: true, download: false },
        scopes: [],
        username: "new-reader",
      },
    });

    await UserEdit.methods.save.call(context, { preventDefault: vi.fn() });

    const payload = mocks.createUser.mock.calls[0][0];
    expect(payload.permissions).toEqual({
      browse: false,
      preview: true,
      download: false,
    });
  });

  it("passes explicit false values to user updates", async () => {
    const context = formContext({
      isNew: false,
      userId: 42,
      user: {
        id: 42,
        loginMethod: "password",
        permissions: { browse: true, preview: false, download: false },
        scopes: [],
        username: "reader",
      },
    });

    await UserEdit.methods.save.call(context, { preventDefault: vi.fn() });

    const payload = mocks.updateUser.mock.calls[0][0];
    expect(payload.permissions).toEqual({
      browse: true,
      preview: false,
      download: false,
    });
  });
});
