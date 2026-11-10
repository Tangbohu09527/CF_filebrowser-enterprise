import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({ bulkDelete: vi.fn(), bulkDeletePublic: vi.fn(), isShare: vi.fn(() => false) }));
vi.mock('@/api', () => ({ resourcesApi: { bulkDelete: mocks.bulkDelete, bulkDeletePublic: mocks.bulkDeletePublic } }));
vi.mock('@/utils/buttons', () => ({ default: { loading: vi.fn(), done: vi.fn(), success: vi.fn() } }));
vi.mock('@/store', () => ({ state: { req: {}, navigation: {} }, getters: { isShare: mocks.isShare, isPreviewView: () => false }, mutations: { closeTopPrompt: vi.fn(), setReload: vi.fn(), resetSelected: vi.fn() } }));
vi.mock('@/notify', () => ({ notify: { showSuccessToast: vi.fn() } }));
vi.mock('@/utils/mimetype', () => ({ getTypeInfo: vi.fn() }));
vi.mock('@/components/files/ListingItem.vue', () => ({ default: {} }));
vi.mock('@/components/LoadingSpinner.vue', () => ({ default: {} }));
vi.mock('@/store/eventBus', () => ({ eventBus: { emit: vi.fn() } }));
vi.mock('@/utils/url', () => ({ default: {} }));

import DeletePrompt from './Delete.vue';

const file = { source: 'source1', path: '/synthetic.png', type: 'image/png' };
function prompt(items = [file]) {
  return { deleting: false, failedItems: [], succeededItems: [], items, itemsToDelete: items, $t: key => key, isItemDone: DeletePrompt.methods.isItemDone };
}

describe('original Web delete prompt uses recycle actions', () => {
  beforeEach(() => { vi.clearAllMocks(); mocks.isShare.mockReturnValue(false); });

  it('routes the original confirmation through the recoverable bulk action', async () => {
    mocks.bulkDelete.mockResolvedValue({ succeeded: [file], failed: [] });
    const instance = prompt();
    await DeletePrompt.methods.submit.call(instance);
    expect(mocks.bulkDelete).toHaveBeenCalledWith([{ ...file, isDir: undefined }]);
    expect(mocks.bulkDeletePublic).not.toHaveBeenCalled();
    expect(instance.succeededItems).toEqual([file]);
  });

  it('never falls back to permanent public DELETE for a share', async () => {
    mocks.isShare.mockReturnValue(true);
    const instance = prompt();
    await DeletePrompt.methods.submit.call(instance);
    expect(mocks.bulkDelete).not.toHaveBeenCalled();
    expect(mocks.bulkDeletePublic).not.toHaveBeenCalled();
    expect(instance.failedItems[0].message).toBe('trash.sharesUnsupported');
  });

  it('does not send successful files again when retrying a partial result', async () => {
    const folder = { source: 'source1', path: '/folder', type: 'directory' };
    mocks.bulkDelete.mockResolvedValueOnce({ succeeded: [file], failed: [{ ...folder, message: 'unsupported directory' }] });
    mocks.bulkDelete.mockResolvedValueOnce({ succeeded: [], failed: [{ ...folder, message: 'unsupported directory' }] });
    const instance = prompt([file, folder]);
    await DeletePrompt.methods.submit.call(instance);
    await DeletePrompt.methods.submit.call(instance);
    expect(mocks.bulkDelete.mock.calls[1][0]).toEqual([{ ...folder, isDir: undefined }]);
    expect(instance.succeededItems).toEqual([file]);
    expect(instance.failedItems).toHaveLength(1);
  });
});
