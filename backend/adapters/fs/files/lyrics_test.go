package files

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gtsteffaniak/filebrowser/backend/indexing/iteminfo"
	"github.com/stretchr/testify/require"
)

func TestExtractLyricsSidecarInjection(t *testing.T) {
	dir := t.TempDir()
	audioPath := filepath.Join(dir, "track.mp3")
	audio := make([]byte, 128)
	copy(audio, []byte("TAG"))
	require.NoError(t, os.WriteFile(audioPath, audio, 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "track.lrc"), []byte("[00:01.00]DISK-SIDECAR\n"), 0644))

	t.Run("missing injection preserves disk fallback", func(t *testing.T) {
		lyrics, err := ExtractLyrics(audioPath)
		require.NoError(t, err)
		require.Equal(t, []string{"DISK-SIDECAR"}, lyricTexts(lyrics))
	})

	t.Run("injected content replaces disk fallback", func(t *testing.T) {
		lyrics, err := ExtractLyrics(audioPath, "[00:02.00]INJECTED-SIDECAR\n")
		require.NoError(t, err)
		require.Equal(t, []string{"INJECTED-SIDECAR"}, lyricTexts(lyrics))
	})

	t.Run("explicit empty injection disables disk fallback", func(t *testing.T) {
		lyrics, err := ExtractLyrics(audioPath, "")
		require.NoError(t, err)
		require.Empty(t, lyrics)
	})

	t.Run("interleaved injections do not retain request content", func(t *testing.T) {
		for _, expected := range []string{"REQUEST-A", "REQUEST-B", "REQUEST-A"} {
			lyrics, err := ExtractLyrics(audioPath, "[00:03.00]"+expected+"\n")
			require.NoError(t, err)
			require.Equal(t, []string{expected}, lyricTexts(lyrics))
		}
	})
}

func lyricTexts(lyrics []iteminfo.Lyric) []string {
	texts := make([]string, len(lyrics))
	for i, lyric := range lyrics {
		texts[i] = lyric.Text
	}
	return texts
}
