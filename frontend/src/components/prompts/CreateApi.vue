<template>
  <div class="card-content">
    <div v-if="createdToken" class="created-token">
      <p class="created-token-warning" role="alert">
        <i class="material-symbols" aria-hidden="true">warning</i>
        <span>{{ $t("api.oneTimeTokenWarning") }}</span>
      </p>
      <div class="created-token-value">
        <code>{{ createdToken }}</code>
        <button
          type="button"
          class="action"
          @click="copyCreatedToken"
          :aria-label="$t('buttons.copyToClipboard')"
          :title="$t('buttons.copyToClipboard')"
        >
          <i class="material-symbols">content_copy</i>
        </button>
      </div>
    </div>
    <div v-else-if="creating" class="loading-content">
      <LoadingSpinner size="small" />
      <p class="loading-text">{{ $t("prompts.operationInProgress") }}</p>
    </div>
    <div v-else>
      <!-- API Key Name Input -->
      <p>{{ $t('general.name') }}</p>
    <input v-focus class="input" type="text" v-model.trim="apiName"
      :placeholder="$t('api.keyNamePlaceholder')" />

    <!-- Duration Input -->
    <p>{{ $t('api.tokenDuration') }}</p>
    <div class="sizeInputWrapper">
      <input class="sizeInput roundedInputLeft input" v-model.number="duration" type="number" min="1"
        :placeholder="$t('api.durationNumberPlaceholder')" />
      <select v-model="unit" class="roundedInputRight input">
        <option value="days">{{ $t('api.days') }}</option>
        <option value="months">{{ $t('api.months') }}</option>
      </select>
    </div>

    <!-- Customize Token Option -->
    <div class="settings-items">
      <ToggleSwitch
        v-model="customizeToken"
        :name="$t('api.customizeToken')"
        class="item"
        :description="$t('api.customizeTokenInfo')"
      />
    </div>

    <!-- Permissions Input (only shown when customizing) -->
    <div v-if="customizeToken">
      <p>{{ $t('api.permissionNote') }}</p>
      <div class="settings-items">
        <ToggleSwitch v-for="permission in Object.keys(localPerms)" :key="permission" class="item"
          v-model="localPerms[permission]" :name="permission" :disabled="!userPermissions[permission]" />
      </div>
    </div>
    </div>
  </div>

  <div class="card-actions">
    <button
      v-if="createdToken"
      type="button"
      class="button button--flat button--blue"
      @click="closeCreatedToken"
      :title="$t('general.close')"
    >
      {{ $t("general.close") }}
    </button>
    <button
      v-else
      type="button"
      class="button button--flat button--blue"
      @click="createAPIKey"
      :disabled="creating"
      :title="$t('general.create')"
    >
      {{ $t("general.create") }}
    </button>
  </div>
</template>

<script>
import { mutations } from "@/store";
import { notify } from "@/notify";
import { authApi } from "@/api";
import ToggleSwitch from "@/components/settings/ToggleSwitch.vue";
import { eventBus } from "@/store/eventBus";
import LoadingSpinner from "@/components/LoadingSpinner.vue";

export default {
  name: "CreateAPI",
  data() {
    return {
      apiName: "",
      duration: 1,
      unit: "days",
      customizeToken: false, // false = minimal token (default), true = customizable/full token
      localPerms: {},
      creating: false,
      createdToken: "",
    };
  },
  components: {
    ToggleSwitch,
    LoadingSpinner,
  },
  props: {
    permissions: {
      type: Object,
      required: true,
    },
    userPermissions: {
      type: Object,
      required: true,
    },
  },
  watch: {
    // Watch prop and update localPerms when changes
    permissions: {
      immediate: true,
      handler(newVal) {
        this.localPerms = { ...newVal };
      }
    }
  },
  computed: {
    durationInDays() {
      // Calculate duration based on unit
      return this.unit === "days" ? this.duration : this.duration * 30; // assuming 30 days per month
    },
  },
  methods: {
    async createAPIKey() {
      this.creating = true;
      try {
        const params = {
          name: this.apiName,
          days: this.durationInDays,
          minimal: !this.customizeToken, // minimal = true when NOT customizing
        };

        // Only include permissions when customizing token
        if (this.customizeToken) {
          // Filter to get keys of permissions set to true and join them as a comma-separated string
          const permissionsString = Object.keys(this.localPerms)
            .filter((key) => this.localPerms[key])
            .join(",");
          params.permissions = permissionsString;
        }

        const response = await authApi.createApiKey(params);
        if (!response?.token) {
          throw new Error("API token creation response did not include a token");
        }
        this.createdToken = response.token;
        // Emit event to refresh API keys list
        eventBus.emit('apiKeysChanged');
        notify.showSuccessToast(this.$t("api.createKeySuccess"));
      } catch (_e) {
        notify.showError(this.$t("api.createKeyFailed"));
      } finally {
        this.creating = false;
      }
    },
    async copyCreatedToken() {
      if (!this.createdToken) {
        return;
      }

      let copied = false;
      if (navigator.clipboard?.writeText) {
        try {
          await navigator.clipboard.writeText(this.createdToken);
          copied = true;
        } catch (_error) {
          // Continue with the browser fallback below.
        }
      }

      if (!copied && this.createdToken) {
        let textArea;
        try {
          textArea = document.createElement("textarea");
          textArea.value = this.createdToken;
          textArea.style.position = "fixed";
          textArea.style.opacity = "0";
          document.body.appendChild(textArea);
          textArea.focus();
          textArea.select();
          copied = document.execCommand("copy");
        } catch (_error) {
          copied = false;
        } finally {
          textArea?.remove();
        }
      }

      if (copied) {
        notify.showSuccessToast(this.$t("buttons.copySuccess"));
      } else {
        notify.showError(this.$t("buttons.copyFailed"));
      }
    },
    closeCreatedToken() {
      this.createdToken = "";
      mutations.closeTopPrompt();
    },
  },
};
</script>
<style scoped>
.sizeInputWrapper {
  display: flex !important;
}
.description {
  font-size: 0.9em;
  color: #666;
  margin-top: 0.5em;
}
.info-text {
  font-style: italic;
  color: #666;
  margin-top: 0.5em;
}

.loading-content {
  text-align: center;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 16px;
  padding-top: 2em;
}

.loading-text {
  padding: 1em;
  margin: 0;
  font-size: 1em;
  font-weight: 500;
}

.card-content {
  position: relative;
}

.created-token {
  display: flex;
  flex-direction: column;
  gap: 1em;
}

.created-token-warning {
  display: flex;
  align-items: flex-start;
  gap: 0.75em;
  margin: 0;
  padding: 0.75em;
  color: var(--textPrimary);
  background: var(--surfaceSecondary);
  border-left: 3px solid var(--warningColor, #ff9800);
  line-height: 1.5;
}

.created-token-warning .material-symbols {
  flex-shrink: 0;
  color: var(--warningColor, #ff9800);
}

.created-token-value {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  align-items: stretch;
  border: 1px solid var(--divider);
  border-radius: 4px;
  background: var(--surfaceSecondary);
}

.created-token-value code {
  min-width: 0;
  padding: 0.75em;
  overflow-wrap: anywhere;
  color: var(--textPrimary);
  user-select: all;
}

.created-token-value .action {
  width: 2.75em;
  min-width: 2.75em;
  border-left: 1px solid var(--divider);
}
</style>
