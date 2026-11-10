<template>
  <section class="trash-page" aria-labelledby="trash-title">
    <header>
      <h1 id="trash-title">{{ $t('trash.title') }}</h1>
      <p>{{ $t('trash.retention') }}</p>
    </header>
    <form class="trash-filters" @submit.prevent="refresh(0)">
      <label>{{ $t('general.source') }}
        <select v-model="source" :disabled="busy" @change="refresh(0)">
          <option v-for="name in sources" :key="name" :value="name">{{ name }}</option>
        </select>
      </label>
      <label class="trash-query">{{ $t('general.search') }}
        <input v-model="query" :placeholder="$t('trash.searchHint')" :disabled="busy" />
      </label>
      <button class="button" :disabled="busy || !source" type="submit">{{ $t('general.update') }}</button>
    </form>
    <p v-if="message" role="status" class="trash-message">{{ message }}</p>
    <p v-if="busy" role="status">{{ $t('general.loading') }}</p>
    <p v-if="!busy && !items.length">{{ $t('trash.empty') }}</p>
    <div v-if="items.length" class="trash-table-wrap">
      <table>
        <thead><tr><th>{{ $t('general.name') }}</th><th>{{ $t('general.status') }}</th><th>{{ $t('general.user') }}</th><th>{{ $t('general.lastUpdate') }}</th><th>{{ $t('trash.restore') }}</th></tr></thead>
        <tbody>
          <tr v-for="item in items" :key="item.operation_id">
            <td><strong>{{ item.name }}</strong><div>{{ item.path }}</div><small>{{ item.size.toLocaleString() }} {{ $t('trash.bytes') }}</small><details><summary>{{ $t('trash.operation') }}</summary><code>{{ item.operation_id }}</code><div v-if="item.restore_operation_id"><code>{{ item.restore_operation_id }}</code></div><div v-if="item.restored_path">{{ item.restored_path }}</div><code>{{ item.sha256 }}</code></details></td>
            <td>{{ statusLabel(item.state) }}<small v-if="item.error_code">{{ item.error_code }}</small></td>
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
    <footer class="trash-actions">
      <button type="button" class="button" :disabled="busy || offset === 0" @click="refresh(offset - 50)">{{ $t('general.previous') }}</button>
      <span>{{ $t('trash.pageCount', { shown: offset + items.length, total }) }}</span>
      <button type="button" class="button" :disabled="busy || offset + items.length >= total" @click="refresh(offset + 50)">{{ $t('general.next') }}</button>
    </footer>
  </section>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue';
import { useI18n } from 'vue-i18n';
import { state } from '@/store';
import { getTrash, listTrash, restoreTrash } from '@/api/trash';

const { t } = useI18n();
const sources = computed(() => (state.user?.scopes || []).map(scope => scope.name));
const canRestore = computed(() => state.user?.permissions?.create && state.user?.permissions?.delete);
const source = ref(sources.value.includes(state.req?.source) ? state.req.source : sources.value[0] || '');
const query = ref('');
const items = ref([]);
const total = ref(0);
const offset = ref(0);
const busy = ref(false);
const message = ref('');
const selected = ref(null);
const destination = ref('');
const uncertain = ref(false);
let restoreId = '';

function statusLabel(status) {
  const labels = { pending_trash: t('trash.pendingTrash'), trashed: t('trash.trashed'), pending_restore: t('trash.pendingRestore'), restored: t('trash.restored'), failed: t('trash.failed'), manual_reconciliation: t('trash.needsReview') };
  return labels[status] || t('trash.needsReview');
}

async function refresh(nextOffset = offset.value) {
  if (!source.value) return;
  busy.value = true;
  try {
    const result = await listTrash(source.value, query.value, nextOffset);
    items.value = result.items;
    total.value = result.total;
    offset.value = nextOffset;
  } catch (error) { message.value = error.message; }
  finally { busy.value = false; }
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
  restoreId ||= crypto.randomUUID();
  try {
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
input, select { padding: .65rem; border: 1px solid var(--border-color, #888); border-radius: .35rem; color: inherit; background: var(--surfaceSecondary, transparent); }
.trash-table-wrap { overflow-x: auto; }
table { border-collapse: collapse; width: 100%; text-align: left; }
td, th { padding: .8rem; border-bottom: 1px solid var(--border-color, #888); vertical-align: top; }
td:first-child { min-width: 14rem; overflow-wrap: anywhere; }
small { display: block; opacity: .75; margin: .4rem 0; }
code { overflow-wrap: anywhere; font-size: .8em; }
.trash-restore { padding: 1.2rem; }
.trash-message { padding: .8rem; border-inline-start: 3px solid currentColor; overflow-wrap: anywhere; }
@media (max-width: 640px) { .trash-page { padding: .8rem; } td, th { padding: .5rem; } }
</style>
