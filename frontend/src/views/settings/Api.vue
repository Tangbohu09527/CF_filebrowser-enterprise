<template>
  <button
    type="button"
    @click.prevent="createPrompt"
    class="button floating-action-button"
  >
    {{ $t("general.new") }}
  </button>
  <errors v-if="error" :errorCode="error.status" />
  <div class="card-title">
    <h2>{{ $t("api.title") }}</h2>
  </div>

  <div class="card-content full">
    <template v-if="links.length > 0">
      <p>
        {{ $t("api.description") }}
        <a class="link" href="swagger/index.html">{{ $t("api.swaggerLinkText") }}</a>
      </p>
    </template>
    <settings-table
      :columns="apiTableColumns"
      :items="links"
      item-key="name"
      default-sort-key="name"
      :aria-label="$t('api.title')"
      :loading="loading"
    >
        <template #cell-issuedAt="{ row }">{{ formatTime(row.issuedAt) }}</template>
        <template #cell-expiresAt="{ row }">{{ formatTime(row.expiresAt) }}</template>
        <template #cell-tokenPrefix="{ row }">
          <code>{{ row.tokenPrefix || '-' }}</code> <!-- eslint-disable-line @intlify/vue-i18n/no-raw-text -->
        </template>
        <template #cell-capabilities="{ row }">{{ capabilityNames(row) }}</template>
        <template #cell-actions="{ row }">
          <div class="api-table-actions">
            <button
              type="button"
              class="action"
              @click.prevent="infoPrompt(row.name, row)"
              :aria-label="$t('api.actions')"
              :title="$t('api.actions')"
            >
              <i class="material-symbols">info</i>
            </button>
          </div>
        </template>
    </settings-table>
  </div>

</template>

<script>
import { authApi } from "@/api";
import { state, mutations } from "@/store";
import Errors from "@/views/Errors.vue";
import SettingsTable from "@/components/settings/Table.vue";
import { eventBus } from "@/store/eventBus";

export default {
  name: "api",
  components: {
    Errors,
    SettingsTable,
  },
  data: () => ({
    error: null,
    links: [],
    user: {
      permissions: { ...state.user.permissions}
    },
    /** Local fetch state; avoids global Settings overlay spinner (table shows its own). */
    loading: true,
  }),
  async created() {
    await this.reloadApiKeys();
  },
  mounted() {
    // Listen for API key changes
    eventBus.on('apiKeysChanged', this.reloadApiKeys);
  },
  beforeUnmount() {
    // Clean up event listener
    eventBus.off('apiKeysChanged', this.reloadApiKeys);
  },
  computed: {
    settings() {
      return state.settings;
    },
    active() {
      return state.activeSettingsView === "shares-main";
    },
    apiTableColumns() {
      return [
        { key: "name", label: this.$t("general.name"), sortable: true },
        { key: "type", label: this.$t("general.type"), sortable: true },
        { key: "tokenPrefix", label: "TokenPrefix", sortable: true },
        {
          key: "issuedAt",
          label: this.$t("api.created"),
          sortable: true,
          sortFn: (a, b) =>
            ((a?.issuedAt ?? 0) - (b?.issuedAt ?? 0)),
        },
        {
          key: "expiresAt",
          label: this.$t("general.expires"),
          sortable: true,
          sortFn: (a, b) =>
            ((a?.expiresAt ?? 0) - (b?.expiresAt ?? 0)),
        },
        { key: "capabilities", label: this.$t("api.permissions") },
        {
          key: "actions",
          label: this.$t("api.actions"),
          align: "right",
          narrow: true,
        },
      ];
    },
  },
  methods: {
    async reloadApiKeys() {
      this.loading = true;
      try {
        // Fetch the API keys from the specified endpoint
        this.links = await authApi.getApiKeys();
        this.error = null; // Clear errors
      } catch (e) {
        if (e.status === 404) {
          this.links = [];
          this.error = null;
        } else {
          this.error = e;
        }
      } finally {
        this.loading = false;
      }
    },
    capabilityNames(row) {
      const names = Object.entries(row.Permissions || {})
        .filter(([, enabled]) => enabled)
        .map(([name]) => name);
      return names.join(", ") || "-";
    },
    createPrompt() {
      mutations.showPrompt({
        name: "CreateApi",
        props: { permissions: this.user.permissions, userPermissions: this.user.permissions },
      });
    },
    infoPrompt(name, info) {
      mutations.showPrompt({ name: "ActionApi", props: { name: name, info: info } });
    },
    formatTime(time) {
      return new Date(time * 1000).toLocaleDateString("en-US", {
        year: "numeric",
        month: "long",
        day: "numeric",
      });
    },
  },
};
</script>
<style>
.api-table-actions {
  display: inline-flex;
  flex-direction: row;
  flex-wrap: nowrap;
  gap: 0.25em;
  justify-content: flex-end;
  align-items: center;
}

.api-table-actions .action {
  flex-shrink: 0;
}
</style>
