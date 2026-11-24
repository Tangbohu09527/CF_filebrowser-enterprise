<template>
  <section class="trash-page" aria-labelledby="trash-title">
    <div class="trash-heading">
      <h1 id="trash-title">{{ $t('trash.title') }}</h1>
      <template v-if="summary">
        <p>{{ $t('trash.usage', { size: formatSize(summary.usage_bytes) }) }}</p>
        <p v-if="summary.retention?.enabled && summary.next_cleanup_at">
          {{ $t('trash.cleanupSchedule', {
            days: summary.retention.days,
            next: cleanupDate(summary.next_cleanup_at),
            size: formatSize(summary.due_bytes),
          }) }}
        </p>
        <p v-else-if="!summary.retention?.enabled">{{ $t('trash.retention') }}</p>
      </template>
    </div>
    <form class="trash-filters" @submit.prevent="refresh(0)">
      <label>{{ $t('general.source') }}
        <select v-model="source" :disabled="busy" @change="changeSource">
          <option v-for="name in sources" :key="name" :value="name">{{ name }}</option>
        </select>
      </label>
      <label class="trash-query">{{ $t('general.search') }}
        <input v-model="query" :placeholder="$t('trash.searchHint')" :disabled="busy" />
      </label>
      <label>{{ $t('trash.sortBy') }}
        <select v-model="sort" :disabled="busy" @change="refresh(0)">
          <option value="">{{ $t('trash.newestFirst') }}</option>
          <option value="size">{{ $t('trash.largestFirst') }}</option>
        </select>
      </label>
      <button class="button" :disabled="busy || !source" type="submit">{{ $t('general.update') }}</button>
    </form>
    <details v-if="summary?.can_manage_retention" class="trash-policy">
      <summary>{{ $t('trash.retentionSettings') }}</summary>
      <form @submit.prevent="saveRetention">
        <div class="trash-actions">
          <label class="trash-retention-toggle">
            <input v-model="retentionEnabled" type="checkbox" :disabled="busy" />
            {{ $t('trash.enableCleanup') }}
          </label>
          <label>{{ $t('trash.retentionDays') }}
            <input v-model.number="retentionDays" type="number" min="1" max="3650" required :disabled="busy" />
          </label>
          <button class="button" type="submit" :disabled="busy || unchangedRetention">
            {{ $t('general.save', { suffix: '' }) }}
          </button>
        </div>
        <p>{{ $t('trash.retentionHint') }}</p>
      </form>
    </details>
    <div v-if="summary?.can_purge" class="trash-actions">
      <button type="button" class="button button--flat button--red" :disabled="busy || !checked.length" @click="openPurge(false)">
        {{ $t('trash.purgeSelected') }}
      </button>
      <button type="button" class="button button--flat button--red" :disabled="busy" @click="openPurge(true)">
        {{ $t('trash.purgeSource') }}
      </button>
    </div>
    <p v-if="message" role="status" class="trash-message">{{ message }}</p>
    <ul v-if="purgeIssues.length" class="trash-purge-issues">
      <li v-for="item in purgeIssues" :key="item.operation_id">
        <strong>{{ item.name }}</strong> {{ purgeIssueLabel(item) }}
      </li>
    </ul>
    <p v-if="busy" role="status">{{ $t('general.loading') }}</p>
    <p v-if="!busy && !items.length">{{ $t('trash.empty') }}</p>
    <div v-if="items.length" class="trash-table-wrap">
      <table>
        <thead>
          <tr>
            <th v-if="summary?.can_purge" class="trash-select">
              <input v-if="eligibleItems.length" type="checkbox" :aria-label="$t('trash.selectPage')"
                :checked="allSelected" :indeterminate="checked.length > 0 && !allSelected"
                :disabled="busy" @change="selectPage($event.target.checked)" />
            </th>
            <th>{{ $t('general.name') }}</th>
            <th>{{ $t('general.status') }}</th>
            <th>{{ $t('general.user') }}</th>
            <th>{{ $t('general.lastUpdate') }}</th>
            <th>{{ $t('trash.actions') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="item in items" :key="item.operation_id">
            <td v-if="summary?.can_purge">
              <input v-if="item.state === 'trashed'" v-model="checked" type="checkbox" :value="item.operation_id"
                :aria-label="$t('trash.selectFile', { name: item.name })" :disabled="busy" />
            </td>
            <td class="trash-file"><strong>{{ item.name }}</strong><div>{{ item.path }}</div><small>{{ item.size.toLocaleString() }} {{ $t('trash.bytes') }}</small><details><summary>{{ $t('trash.operation') }}</summary><code>{{ item.operation_id }}</code><div v-if="item.restore_operation_id"><code>{{ item.restore_operation_id }}</code></div><div v-if="item.restored_path">{{ item.restored_path }}</div><code>{{ item.sha256 }}</code></details></td>
            <td>
              {{ statusLabel(item.state) }}
              <small v-if="item.state === 'trashed' && item.expires_at">
                {{ $t('trash.expiresOn', { date: cleanupDate(item.expires_at) }) }}
              </small>
              <small v-if="item.purged_at">{{ purgeDescription(item) }}</small>
              <small v-if="item.error_code">{{ item.error_code }}</small>
            </td>
            <td>{{ item.actor }}</td>
            <td>{{ new Date(item.updated_at).toLocaleString() }}</td>
            <td><button v-if="item.state === 'trashed' && canRestore" type="button" class="button" :disabled="busy" @click="selectRestore(item)">{{ $t('trash.restore') }}</button><button v-if="item.state.startsWith('pending_')" type="button" class="button" :disabled="busy" @click="check(item)">{{ $t('trash.checkOperation') }}</button></td>
          </tr>
        </tbody>
      </table>
    </div>
    <form v-if="selected" class="trash-restore card" @submit.prevent="restore">
      <h2>{{ $t('trash.restoreFile', { name: selected.name }) }}</h2>
      <p>{{ $t('trash.restoreHint') }}</p>
      <label>{{ $t('trash.destination') }}<input v-model="destination" required :disabled="busy || uncertain" /></label>
      <div class="trash-actions">
        <button type="submit" class="button" :disabled="busy || uncertain">{{ $t('general.confirm') }}</button>
        <button v-if="uncertain" type="button" class="button" :disabled="busy" @click="check(selected)">{{ $t('trash.checkOperation') }}</button>
        <button type="button" class="button" :disabled="busy" @click="selected = null">{{ $t('general.close') }}</button>
      </div>
    </form>
    <dialog ref="purgeDialog" class="trash-purge-dialog" aria-labelledby="trash-purge-title" @cancel="cancelIfBusy" @close="purgeSelection = null">
      <form v-if="purgeSelection" @submit.prevent="confirmPurge">
        <h2 id="trash-purge-title">{{ purgeSelection.entireSource ? $t('trash.purgeSource') : $t('trash.purgeSelected') }}</h2>
        <p>{{ $t('trash.purgeConfirm', {
          source: purgeSelection.source,
          count: purgeSelection.items.length,
          size: formatSize(purgeSelection.size),
        }) }}</p>
        <div class="trash-actions">
          <button class="button button--flat" type="button" :disabled="busy" autofocus @click="purgeDialog.close()">
            {{ $t('general.cancel', { suffix: '' }) }}
          </button>
          <button class="button button--red" type="submit" :disabled="busy">
            {{ $t('trash.purgeNow') }}
          </button>
        </div>
      </form>
    </dialog>
    <footer class="trash-actions">
      <button type="button" class="button" :disabled="busy || offset === 0" @click="refresh(offset - 50)">{{ $t('general.previous') }}</button>
      <span>{{ $t('trash.pageCount', { shown: offset + items.length, total }) }}</span>
      <button type="button" class="button" :disabled="busy || offset + items.length >= total" @click="refresh(offset + 50)">{{ $t('general.next') }}</button>
    </footer>
  </section>
</template>

<script setup>
import { computed, nextTick, onMounted, ref } from 'vue';
import { useI18n } from 'vue-i18n';
import { state } from '@/store';
import { getTrash, listTrash, previewTrashPurge, purgeTrash, restoreTrash, setTrashRetention } from '@/api/trash';
import { getHumanReadableFilesize } from '@/utils/filesizes';
import { randomUuid } from '@/utils/randomUuid';

const { t } = useI18n();
const sources = computed(() => (state.user?.scopes || []).map(scope => scope.name));
const canRestore = computed(() => state.user?.permissions?.create && state.user?.permissions?.delete);
const source = ref(sources.value.includes(state.req?.source) ? state.req.source : sources.value[0] || '');
const query = ref('');
const sort = ref('');
const items = ref([]);
const total = ref(0);
const offset = ref(0);
const busy = ref(false);
const message = ref('');
const summary = ref(null);
const retentionDays = ref(30);
const retentionEnabled = ref(false);
const selected = ref(null);
const destination = ref('');
const uncertain = ref(false);
const checked = ref([]);
const purgeSelection = ref(null);
const purgeDialog = ref(null);
const purgeIssues = ref([]);
const eligibleItems = computed(() => items.value.filter(item => item.state === 'trashed'));
const allSelected = computed(() => eligibleItems.value.length > 0 && checked.value.length === eligibleItems.value.length);
const unchangedRetention = computed(() => retentionEnabled.value === summary.value?.retention?.enabled &&
  Number(retentionDays.value) === summary.value.retention.days);
let restoreId = '';

function statusLabel(status) {
  const labels = {
    pending_trash: t('trash.pendingTrash'),
    trashed: t('trash.trashed'),
    pending_restore: t('trash.pendingRestore'),
    restored: t('trash.restored'),
    failed: t('trash.failed'),
    manual_reconciliation: t('trash.needsReview'),
    pending_purge: t('trash.pendingPurge'),
    purged: t('trash.purged'),
    unknown: t('trash.unknownResult'),
  };
  return labels[status] || t('trash.needsReview');
}

function formatSize(bytes) {
  return bytes < 1024 ? `${bytes.toLocaleString()} ${t('trash.bytes')}` : getHumanReadableFilesize(bytes);
}

function cleanupDate(value) {
  return new Date(value).toLocaleString(undefined, {
    timeZone: 'Asia/Shanghai',
    year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit',
    hourCycle: 'h23',
  });
}

function purgeDescription(item) {
  const time = new Date(item.purged_at).toLocaleString();
  return item.purge_method === 'automatic'
    ? t('trash.purgedAutomatically', { time })
    : t('trash.purgedManually', { time, actor: item.purge_actor });
}

function purgeIssueLabel(item) {
  if (item.error === 'forbidden') return t('trash.purgeForbidden');
  if (item.error === 'not_found') return t('trash.purgeNotFound');
  if (item.error === 'conflict') return t('trash.purgeConflict');
  return statusLabel(item.state);
}

async function refresh(nextOffset = offset.value) {
  if (!source.value) return;
  busy.value = true;
  try {
    const result = await listTrash(source.value, query.value, nextOffset, sort.value);
    items.value = result.items;
    total.value = result.total;
    offset.value = Math.min(nextOffset, result.total);
    summary.value = result;
    retentionDays.value = result.retention?.days ?? 30;
    retentionEnabled.value = result.retention?.enabled === true;
    checked.value = [];
  } catch (error) {
    summary.value = null;
    items.value = [];
    total.value = 0;
    offset.value = 0;
    checked.value = [];
    message.value = error.message;
  }
  finally { busy.value = false; }
}

function changeSource() {
  selected.value = null;
  restoreId = '';
  uncertain.value = false;
  summary.value = null;
  items.value = [];
  total.value = 0;
  offset.value = 0;
  checked.value = [];
  purgeIssues.value = [];
  message.value = '';
  return refresh(0);
}

async function saveRetention() {
  if (busy.value || !summary.value?.can_manage_retention || unchangedRetention.value) return;
  busy.value = true;
  try {
    const retention = await setTrashRetention(source.value, Number(retentionDays.value), retentionEnabled.value);
    summary.value = { ...summary.value, retention };
    message.value = t('trash.retentionSaved');
  } catch (error) {
    message.value = error.message;
  } finally {
    busy.value = false;
  }
  await refresh();
}

function selectPage(select) {
  checked.value = select ? eligibleItems.value.map(item => item.operation_id) : [];
}

async function openPurge(entireSource) {
  if (busy.value || !summary.value?.can_purge) return;
  busy.value = true;
  message.value = '';
  purgeIssues.value = [];
  try {
    const itemsToPurge = entireSource
      ? await previewTrashPurge(source.value)
      : eligibleItems.value.filter(item => checked.value.includes(item.operation_id));
    if (!itemsToPurge.length) {
      message.value = t('trash.noPurgeItems');
      return;
    }
    purgeSelection.value = {
      entireSource,
      source: source.value,
      items: itemsToPurge,
      size: itemsToPurge.reduce((sum, item) => sum + item.size, 0),
    };
    busy.value = false;
    await nextTick();
    purgeDialog.value.showModal();
  } catch (error) {
    message.value = error.message;
  } finally {
    busy.value = false;
  }
}

function cancelIfBusy(event) {
  if (busy.value) event.preventDefault();
}

async function confirmPurge() {
  if (busy.value || !purgeSelection.value) return;
  const selection = purgeSelection.value;
  busy.value = true;
  let completed = 0;
  let interrupted = false;
  try {
    for (let start = 0; start < selection.items.length; start += 50) {
      const batch = selection.items.slice(start, start + 50);
      try {
        const result = await purgeTrash(selection.source, batch.map(item => item.operation_id));
        const outcome = new Map(result.items.map(item => [item.operation_id, item]));
        for (const item of batch) {
          const current = outcome.get(item.operation_id);
          if (current?.state === 'purged') completed++;
          else purgeIssues.value.push({ ...item, state: current?.state ?? 'unknown', error: current?.error });
        }
      } catch {
        purgeIssues.value.push(...batch.map(item => ({ ...item, state: 'unknown' })));
        interrupted = true;
        break;
      }
    }
    message.value = interrupted
      ? t('trash.purgeInterrupted', { count: completed })
      : t('trash.purgeResult', { count: completed, other: purgeIssues.value.length });
  } finally {
    purgeDialog.value.close();
    purgeSelection.value = null;
    busy.value = false;
  }
  await refresh(0);
}

function selectRestore(item) {
  selected.value = item;
  destination.value = item.path;
  restoreId = '';
  uncertain.value = false;
  message.value = '';
}

async function check(item) {
  busy.value = true;
  try {
    const result = await getTrash(source.value, item.operation_id);
    message.value = statusLabel(result.state);
    uncertain.value = result.state.startsWith('pending_') || result.state === 'manual_reconciliation';
    if (!uncertain.value) { selected.value = null; restoreId = ''; }
  } catch (error) { message.value = error.message; }
  finally { busy.value = false; }
  await refresh();
}

async function restore() {
  if (busy.value || uncertain.value || !selected.value) return;
  busy.value = true;
  try {
    restoreId ||= randomUuid();
    const result = await restoreTrash(source.value, selected.value.operation_id, destination.value, restoreId);
    if (result.state !== 'restored') { uncertain.value = true; message.value = t('trash.unknownResult'); }
    else { selected.value = null; message.value = t('trash.restored'); }
  } catch (error) { uncertain.value = true; message.value = error.status === 409 ? t('trash.restoreConflict') : t('trash.unknownResult'); }
  finally { busy.value = false; }
  await refresh();
}

onMounted(() => refresh(0));
</script>

<style scoped>
.trash-page { max-width: 1200px; margin: 0 auto; padding: 1.5rem; }
.trash-filters, .trash-actions { display: flex; align-items: end; gap: 1rem; flex-wrap: wrap; margin: 1.2rem 0; }
.trash-query { flex: 1; min-width: 12rem; }
label { display: flex; flex-direction: column; gap: .4rem; }
input:not([type=checkbox]), select { padding: .65rem; border: 1px solid var(--border-color, #888); border-radius: .35rem; color: inherit; background: var(--surfaceSecondary, transparent); }
.trash-policy summary { cursor: pointer; }
.trash-policy p { margin: .4rem 0; }
.trash-retention-toggle { flex-direction: row; align-items: center; align-self: center; }
.trash-select { width: 2.5rem; }
.trash-table-wrap { overflow-x: auto; }
table { border-collapse: collapse; width: 100%; text-align: left; }
td, th { padding: .8rem; border-bottom: 1px solid var(--border-color, #888); vertical-align: top; }
.trash-file { min-width: 14rem; overflow-wrap: anywhere; }
small { display: block; opacity: .75; margin: .4rem 0; }
code { overflow-wrap: anywhere; font-size: .8em; }
.trash-restore { padding: 1.2rem; }
.trash-message { padding: .8rem; border-inline-start: 3px solid currentColor; overflow-wrap: anywhere; }
.trash-purge-issues { overflow-wrap: anywhere; }
.trash-purge-dialog {
  position: fixed;
  inset: 0;
  margin: auto;
  padding: 1.4rem;
  border: 1px solid var(--border-color, #888);
  border-radius: .6rem;
  max-width: min(34rem, calc(100vw - 2rem));
  color: inherit;
  background: var(--background, Canvas);
}
.trash-purge-dialog::backdrop { background: rgb(0 0 0 / .45); }
.trash-purge-dialog h2 { margin-top: 0; }
.trash-purge-dialog p { overflow-wrap: anywhere; }
.trash-purge-dialog .trash-actions { justify-content: end; margin-bottom: 0; }
@media (max-width: 640px) { .trash-page { padding: .8rem; } td, th { padding: .5rem; } }
</style>
