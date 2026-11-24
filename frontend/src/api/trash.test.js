import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest';

vi.mock('@/i18n', () => ({ default: { global: { t: (key, values) => `${key} ${values?.operation || ''}` } } }));
vi.mock('@/store', () => ({ state: { user: { id: 71 } } }));
vi.mock('@/utils/url', () => ({ getApiPath: (endpoint, params) => `/api/${endpoint}${params ? `?${new URLSearchParams(params)}` : ''}` }));
vi.mock('./utils', () => ({ fetchJSON: vi.fn() }));

import { fetchJSON } from './utils';
import { listTrash, previewTrashPurge, purgeTrash, restoreTrash, setTrashRetention, trashFiles } from './trash';

const file = { source: 'source1', path: '/images/synthetic.jpg', type: 'image/jpeg' };
const key = `filebrowser-trash:71:${file.source}:${file.path}`;

describe('durable Web recycle actions', () => {
  beforeEach(() => {
    localStorage.clear();
    vi.clearAllMocks();
    vi.stubGlobal('crypto', { randomUUID: () => 'synthetic-trash-operation' });
  });
  afterEach(() => vi.unstubAllGlobals());

  it('moves the file through explicit trash POST and persists the ID before sending', async () => {
    fetchJSON.mockImplementation(async (_url, opts) => {
      expect(localStorage.getItem(key)).toBe('synthetic-trash-operation');
      expect(opts.method).toBe('POST');
      expect(JSON.parse(opts.body)).toEqual({ source: file.source, path: file.path, operation_id: 'synthetic-trash-operation' });
      return { state: 'trashed' };
    });
    const result = await trashFiles([file]);
    expect(result.succeeded).toHaveLength(1);
    expect(result.failed).toHaveLength(0);
    expect(fetchJSON.mock.calls[0][0]).toBe('/api/trash');
    expect(localStorage.getItem(key)).toBeNull();
  });

  it('rejects directories and reports partial failure without permanent DELETE', async () => {
    fetchJSON.mockResolvedValue({ state: 'trashed' });
    const result = await trashFiles([file, { source: 'source1', path: '/folder', type: 'directory' }]);
    expect(result.succeeded).toHaveLength(1);
    expect(result.failed).toHaveLength(1);
    expect(result.failed[0].message).toContain('trash.directoriesUnsupported');
    expect(fetchJSON).toHaveBeenCalledTimes(1);
  });

  it('queries an unknown result and never blindly repeats a completed move', async () => {
    fetchJSON.mockRejectedValueOnce(new TypeError('network interrupted'));
    const failed = await trashFiles([file]);
    expect(failed.failed[0].operation_id).toBe('synthetic-trash-operation');
    expect(localStorage.getItem(key)).toBe('synthetic-trash-operation');
    fetchJSON.mockResolvedValueOnce({ state: 'trashed' });
    const retried = await trashFiles([file]);
    expect(retried.succeeded).toHaveLength(1);
    expect(fetchJSON).toHaveBeenCalledTimes(2);
    expect(fetchJSON.mock.calls[1][0]).toContain('/api/trash/synthetic-trash-operation?source=source1');
    expect(fetchJSON.mock.calls[1][1]).toBeUndefined();
  });

  it('can move a file over LAN HTTP without randomUUID', async () => {
    vi.stubGlobal('crypto', { getRandomValues: (bytes) => bytes.fill(255) });
    fetchJSON.mockResolvedValue({ state: 'trashed' });
    const result = await trashFiles([file]);
    expect(result.failed).toEqual([]);
    expect(JSON.parse(fetchJSON.mock.calls[0][1].body).operation_id)
      .toBe('ffffffff-ffff-4fff-bfff-ffffffffffff');
  });

  it('reuses the original ID only after the status query confirms no record', async () => {
    localStorage.setItem(key, 'previous-unknown-operation');
    fetchJSON.mockRejectedValueOnce(Object.assign(new Error('not recorded'), { status: 404 }));
    fetchJSON.mockResolvedValueOnce({ state: 'trashed' });
    const result = await trashFiles([file]);
    expect(result.succeeded).toHaveLength(1);
    expect(JSON.parse(fetchJSON.mock.calls[1][1].body).operation_id).toBe('previous-unknown-operation');
  });

  it('does not re-trash an item restored while the original response was unknown', async () => {
    localStorage.setItem(key, 'previous-unknown-operation');
    fetchJSON.mockResolvedValue({ state: 'restored' });
    const result = await trashFiles([file]);
    expect(result.succeeded).toHaveLength(0);
    expect(result.failed).toHaveLength(1);
    expect(fetchJSON).toHaveBeenCalledTimes(1);
    expect(fetchJSON.mock.calls[0][1]).toBeUndefined();
  });

  it('treats a purged recycle operation as final and never deletes a same-path replacement', async () => {
    localStorage.setItem(key, 'previous-unknown-operation');
    fetchJSON.mockResolvedValue({ state: 'purged' });
    const result = await trashFiles([file]);
    expect(result.succeeded).toHaveLength(0);
    expect(result.failed).toHaveLength(1);
    expect(fetchJSON).toHaveBeenCalledTimes(1);
    expect(fetchJSON.mock.calls[0][1]).toBeUndefined();
    expect(localStorage.getItem(key)).toBeNull();
  });

  it('restores to the explicit target with its persistent restore operation ID', async () => {
    fetchJSON.mockResolvedValue({ state: 'restored' });
    await restoreTrash('source1', 'trash-operation-001', '/images/restored.jpg', 'restore-operation-001');
    const [url, options] = fetchJSON.mock.calls[0];
    expect(url).toBe('/api/trash/trash-operation-001/restore');
    expect(JSON.parse(options.body)).toEqual({ source: 'source1', path: '/images/restored.jpg', restore_operation_id: 'restore-operation-001' });
    await listTrash('source1', 'synthetic', 50);
    expect(fetchJSON.mock.calls[1][0]).toContain('offset=50&limit=50');
  });

  it('uses server-side size sorting and saves retention for the selected Source', async () => {
    fetchJSON.mockResolvedValue({});
    await listTrash('source1', '', 0, 'size');
    expect(fetchJSON.mock.calls[0][0]).toBe('/api/trash?source=source1&query=&offset=0&limit=50&sort=size');
    await setTrashRetention('source1', 30, false);
    const [url, options] = fetchJSON.mock.calls[1];
    expect(url).toBe('/api/trash/retention');
    expect(options.method).toBe('PUT');
    expect(JSON.parse(options.body)).toEqual({ source: 'source1', days: 30, enabled: false });
  });

  it('uses only the previewed IDs when permanently deleting files from a Source', async () => {
    const first = { operation_id: 'first-operation', size: 7 };
    const second = { operation_id: 'second-operation', size: 9 };
    const summary = { total: 2, size: 16, snapshot: 'same-id-set' };
    fetchJSON.mockResolvedValueOnce({ ...summary, items: [first] });
    fetchJSON.mockResolvedValueOnce({ ...summary, items: [second] });
    fetchJSON.mockResolvedValueOnce({ items: [] });
    const preview = await previewTrashPurge('source1');
    expect(preview).toEqual([first, second]);
    expect(fetchJSON.mock.calls[0][0]).toBe('/api/trash/purge/preview?source=source1&offset=0&limit=200');
    expect(fetchJSON.mock.calls[1][0]).toBe('/api/trash/purge/preview?source=source1&offset=1&limit=200');
    await purgeTrash('source1', preview.map(item => item.operation_id));
    const [url, options] = fetchJSON.mock.calls[2];
    expect(url).toBe('/api/trash/purge');
    expect(options.method).toBe('POST');
    expect(JSON.parse(options.body)).toEqual({ source: 'source1', operation_ids: ['first-operation', 'second-operation'] });
  });

  it('rejects a clear preview when the file set changes between pages despite identical count and size', async () => {
    fetchJSON.mockResolvedValueOnce({ total: 2, size: 16, snapshot: 'old-id-set', items: [{ operation_id: 'first-operation', size: 7 }] });
    fetchJSON.mockResolvedValueOnce({ total: 2, size: 16, snapshot: 'new-id-set', items: [{ operation_id: 'second-operation', size: 9 }] });
    await expect(previewTrashPurge('source1')).rejects.toThrow('trash.purgePreviewChanged');
    expect(fetchJSON).toHaveBeenCalledTimes(2);
  });
});
