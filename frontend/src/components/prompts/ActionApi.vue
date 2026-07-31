<template>
  <div class="card-content api-content">
    <div class="api-section">
      <h3 class="section-title">{{ $t('general.info') }}</h3>
      <div class="info-item">
        <span class="info-label">{{ $t('general.name') }}</span>
        <span class="info-value">{{ name }}</span>
      </div>
      <div class="info-item">
        <span class="info-label">{{ $t('general.type') }}</span>
        <span class="info-value">{{ info.type }}</span>
      </div>
      <div class="info-item">
        <span class="info-label">TokenPrefix</span> <!-- eslint-disable-line @intlify/vue-i18n/no-raw-text -->
        <code class="info-value">{{ info.tokenPrefix || '-' }}</code> <!-- eslint-disable-line @intlify/vue-i18n/no-raw-text -->
      </div>
      <div class="info-item">
        <span class="info-label">{{ $t('api.createdAt') }}</span>
        <span class="info-value">{{ formatTime(info.issuedAt) }}</span>
      </div>
      <div class="info-item">
        <span class="info-label">{{ $t('api.expiresAt') }}</span>
        <span class="info-value">{{ formatTime(info.expiresAt) }}</span>
      </div>
    </div>

    <div class="api-section">
      <h3 class="section-title">{{ $t('api.permissions') }}</h3>
      <p class="capabilities">{{ capabilityNames }}</p>
    </div>
  </div>

  <div class="card-actions">
    <button
      type="button"
      class="button button--flat button--red"
      @click="deleteApi"
      :disabled="deleting"
      :title="$t('general.delete')"
    >
      {{ $t('general.delete') }}
    </button>
  </div>
</template>

<script>
import { mutations } from "@/store";
import { notify } from "@/notify";
import { authApi } from "@/api";
import { eventBus } from "@/store/eventBus";

export default {
  name: "ActionApi",
  data() {
    return {
      deleting: false,
    };
  },
  props: {
    name: {
      type: String,
      required: true,
    },
    info: {
      type: Object,
      required: true,
    },
  },
  computed: {
    capabilityNames() {
      const names = Object.entries(this.info.Permissions || {})
        .filter(([, enabled]) => enabled)
        .map(([name]) => name);
      return names.join(", ") || "-";
    },
  },
  methods: {
    formatTime(timestamp) {
      return new Date(timestamp * 1000).toLocaleDateString("en-US", {
        year: "numeric",
        month: "long",
        day: "numeric",
      });
    },
    async deleteApi() {
      if (this.deleting) {
        return;
      }
      this.deleting = true;
      try {
        await authApi.deleteApiKey({ name: this.name });
        eventBus.emit('apiKeysChanged');
        mutations.closeTopPrompt();
        notify.showSuccessToast(this.$t("api.apiKeyDeleted"));
      } catch (_error) {
        // The API layer reports the error; keep this prompt open for retry.
      } finally {
        this.deleting = false;
      }
    },
  },
};
</script>
<style scoped>
.api-content {
  overflow-y: auto;
}

.api-section {
  margin-bottom: 2em;
}

.api-section:last-child {
  margin-bottom: 0;
}

.section-title {
  font-size: 0.95em;
  font-weight: 600;
  color: var(--textPrimary);
  margin: 0 0 0.75em 0;
  padding-bottom: 0.5em;
  border-bottom: 1px solid var(--divider);
}

.info-item {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0.75em 0.5em;
  border-radius: 4px;
  transition: background-color 0.2s;
}

.info-item:hover {
  background-color: var(--surfaceSecondary);
}

.info-label {
  font-weight: 500;
  color: var(--textSecondary);
  font-size: 0.9em;
}

.info-value {
  color: var(--textPrimary);
  font-size: 0.9em;
  text-align: right;
}

.capabilities {
  margin: 0;
  color: var(--textPrimary);
  overflow-wrap: anywhere;
}

/* Responsive adjustments */
@media (max-width: 768px) {
  .info-item {
    flex-direction: column;
    align-items: flex-start;
    gap: 0.25em;
  }

  .info-value {
    text-align: left;
  }
}
</style>
