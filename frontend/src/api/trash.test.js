import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest';

vi.mock('@/i18n', () => ({ default: { global: { t: (key, values) => `${key} ${values?.operation || ''}` } } }));
vi.mock('@/store', () => ({ state: { user: { id: 71 } } }));
vi.mock('@/utils/url', () => ({ getApiPath: (endpoint, params) => `/api/${endpoint}${params ? `?${new URLSearchParams(params)}` : ''}` }));
vi.mock('./utils', () => ({ fetchJSON: vi.fn() }));

import { fetchJSON } from './utils';
import { trashFiles, restoreTrash, listTrash } from './trash';

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

  it('restores to the explicit target with its persistent restore operation ID', async () => {
    fetchJSON.mockResolvedValue({ state: 'restored' });
    await restoreTrash('source1', 'trash-operation-001', '/images/restored.jpg', 'restore-operation-001');
    const [url, options] = fetchJSON.mock.calls[0];
    expect(url).toBe('/api/trash/trash-operation-001/restore');
    expect(JSON.parse(options.body)).toEqual({ source: 'source1', path: '/images/restored.jpg', restore_operation_id: 'restore-operation-001' });
    await listTrash('source1', 'synthetic', 50);
    expect(fetchJSON.mock.calls[1][0]).toContain('offset=50&limit=50');
  });
});
