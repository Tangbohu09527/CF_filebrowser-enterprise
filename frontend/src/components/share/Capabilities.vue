<template>
  <ul class="share-capabilities" :aria-label="$t('settings.permissions-name')">
    <li
      v-for="item in items"
      :key="item.key"
      class="share-capability"
      :class="{ reduced: item.reduced }"
      :data-capability="item.key"
      :data-enabled="String(item.enabled)"
    >
      <span class="capability-label">{{ $t(labelKeys[item.key]) }}</span>
      <span class="capability-state">
        {{ item.enabled ? $t("general.yes") : $t("index.unavailable") }}
      </span>
      <i
        v-if="item.reduced"
        class="material-symbols capability-warning"
        :aria-label="reductionNotice"
        :title="reductionNotice"
      >warning</i>
    </li>
    <li v-if="hasReduction" class="capability-reduction-notice">
      <i class="material-symbols" aria-hidden="true">warning</i>
      <span>{{ reductionNotice }}</span>
    </li>
  </ul>
</template>

<script>
import {
  SHARE_CAPABILITY_LABEL_KEYS,
  effectiveCapabilityItems,
} from "@/utils/shareCapabilities";

const CAPABILITY_REDUCTION_NOTICE =
  "Configured access is limited by the owner's current permissions or the Share security snapshot.";

export default {
  name: "ShareCapabilities",
  props: {
    capabilities: {
      type: Object,
      required: true,
    },
    configuredCapabilities: {
      type: Object,
      required: true,
    },
  },
  computed: {
    labelKeys() {
      return SHARE_CAPABILITY_LABEL_KEYS;
    },
    items() {
      return effectiveCapabilityItems({
        effectiveCapabilities: this.capabilities,
        configuredCapabilities: this.configuredCapabilities,
      });
    },
    hasReduction() {
      return this.items.some((item) => item.reduced);
    },
    reductionNotice() {
      return CAPABILITY_REDUCTION_NOTICE;
    },
  },
};
</script>

<style scoped>
.share-capabilities {
  display: grid;
  gap: 0.25rem;
  margin: 0;
  padding: 0;
  list-style: none;
  text-align: left;
}

.share-capability {
  display: grid;
  grid-template-columns: minmax(6rem, 1fr) auto 1.25rem;
  align-items: center;
  gap: 0.375rem;
  min-height: 1.25rem;
  font-size: 0.8125rem;
  line-height: 1.25rem;
}

.capability-label,
.capability-state {
  overflow-wrap: anywhere;
}

.capability-state {
  opacity: 0.72;
}

.capability-warning {
  width: 1.25rem;
  font-size: 1.125rem;
  line-height: 1.25rem;
}

.capability-reduction-notice {
  display: flex;
  align-items: flex-start;
  gap: 0.375rem;
  margin-top: 0.25rem;
  font-size: 0.75rem;
  line-height: 1.15rem;
}

.capability-reduction-notice .material-symbols {
  flex: 0 0 auto;
  font-size: 1rem;
  line-height: 1.15rem;
}
</style>
