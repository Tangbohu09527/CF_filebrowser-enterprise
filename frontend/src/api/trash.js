import i18n from '@/i18n';
import { state } from '@/store';
import { getApiPath } from '@/utils/url';
import { randomUuid } from '@/utils/randomUuid';
import { fetchJSON } from './utils';

export function listTrash(source, query = '', offset = 0, sort = '') {
  const params = { source, query, offset, limit: 50 };
  if (sort) params.sort = sort;
  return fetchJSON(getApiPath('trash', params));
}

export function getTrash(source, operationId) {
  return fetchJSON(getApiPath(`trash/${encodeURIComponent(operationId)}`, { source }));
}

export function restoreTrash(source, operationId, path, restoreOperationId) {
  return fetchJSON(getApiPath(`trash/${encodeURIComponent(operationId)}/restore`), {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ source, path, restore_operation_id: restoreOperationId }),
  });
}

export async function previewTrashPurge(source) {
  const loadPage = offset => fetchJSON(getApiPath('trash/purge/preview', { source, offset, limit: 200 }));
  const firstPage = await loadPage(0);
  const { total, size, snapshot } = firstPage;
  const items = [...firstPage.items];
  while (items.length < total) {
    const page = await loadPage(items.length);
    if (page.total !== total || page.size !== size || page.snapshot !== snapshot || !page.items.length) {
      throw new Error(i18n.global.t('trash.purgePreviewChanged'));
    }
    items.push(...page.items);
  }
  const uniqueIds = new Set(items.map(item => item.operation_id));
  const totalSize = items.reduce((sum, item) => sum + item.size, 0);
  if (!snapshot || items.length !== total || uniqueIds.size !== total || totalSize !== size) {
    throw new Error(i18n.global.t('trash.purgePreviewChanged'));
  }
  return items;
}

export function purgeTrash(source, operationIds) {
  return fetchJSON(getApiPath('trash/purge'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ source, operation_ids: operationIds }),
  });
}

export function setTrashRetention(source, days, enabled) {
  return fetchJSON(getApiPath('trash/retention'), {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ source, days, enabled }),
  });
}

// Persist the request ID before sending. A new click after an unknown response
// first queries the old operation and reuses its ID only when it was not recorded.
export async function trashFiles(items) {
  const result = { succeeded: [], failed: [] };
  for (const item of items) {
    const key = `filebrowser-trash:${state.user?.id}:${item.source}:${item.path}`;
    let operationId;
    try {
      if (item.isDir || item.type === 'directory') throw new Error(i18n.global.t('trash.directoriesUnsupported'));
      operationId = localStorage.getItem(key);
      let entry;
      if (operationId) {
        try { entry = await getTrash(item.source, operationId); }
        catch (error) { if (error.status !== 404) throw error; }
      } else {
        operationId = randomUuid();
        localStorage.setItem(key, operationId);
      }
      if (!entry) {
        entry = await fetchJSON(getApiPath('trash'), {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ source: item.source, path: item.path, operation_id: operationId }),
        });
      }
      if (entry.state === 'trashed') {
        localStorage.removeItem(key);
        result.succeeded.push({ ...item, operation_id: operationId });
      } else {
        if (['restored', 'purged', 'failed', 'manual_reconciliation'].includes(entry.state)) localStorage.removeItem(key);
        throw new Error(i18n.global.t('trash.reviewOperation', { operation: operationId, state: entry.state }));
      }
    } catch (error) {
      // Definitive authorization/validation failures cannot have started a move.
      if ([400, 403].includes(error.status)) localStorage.removeItem(key);
      const message = operationId && ![400, 403].includes(error.status)
        ? `${error.message} ${i18n.global.t('trash.reviewOperation', { operation: operationId, state: 'unknown' })}`
        : error.message;
      result.failed.push({ ...item, operation_id: operationId, message });
    }
  }
  return result;
}
