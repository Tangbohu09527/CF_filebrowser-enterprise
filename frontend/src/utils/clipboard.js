// Copy to clipboard.
// Uses clipboard API when available, and will fallback to execCommand (which is deprecated, but will make it work on insecure connections)

import i18n from '@/i18n';
import { notify } from '@/notify';

/**
 * @param {string} text - Text to copy.
 * @returns {Promise<boolean>} True if copy succeeded, false otherwise.
 */
export async function copyToClipboard(text) {
  const successMessage = i18n.global.t('buttons.copySuccess');
  const errorMessage = i18n.global.t('buttons.copyFailed');

  if (navigator.clipboard) {
    try {
      await navigator.clipboard.writeText(text);
      notify.showSuccessToast(successMessage);
      return true;
    } catch (_err) {
      // Fallback to execCommand
    }
  }

  let textArea;
  try {
    textArea = document.createElement('textarea');
    textArea.value = text;
    textArea.style.position = 'fixed';
    textArea.style.opacity = '0';
    document.body.appendChild(textArea);
    textArea.focus();
    textArea.select();

    const success = document.execCommand('copy');
    if (success) {
      notify.showSuccessToast(successMessage);
      return true;
    }

    notify.showError(errorMessage);
    return false;
  } catch (_err) {
    notify.showError(errorMessage);
    return false;
  } finally {
    textArea?.remove();
  }
}
