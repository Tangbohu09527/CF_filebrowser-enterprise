package preview

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"image"
	"image/color"
	"image/gif"
	"image/jpeg"
	"image/png"
	"io"
	"os"
	"testing"

	"github.com/gtsteffaniak/filebrowser/backend/adapters/fs/fileutils"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
	"golang.org/x/image/bmp"
	"golang.org/x/image/tiff"
)

func TestMain(m *testing.M) {
	// Ensure fileutils permissions are set (needed by NewPreviewGenerator)
	if fileutils.PermDir == 0 {
		fileutils.SetFsPermissions(0644, 0755)
	}

	// Run the tests
	code := m.Run()

	// Exit with the test result code
	os.Exit(code)
}

func TestService_Resize(t *testing.T) {
	testCases := map[string]struct {
		options ResizeOptions
		source  func(t *testing.T) afero.File
		matcher func(t *testing.T, reader io.Reader)
		wantErr bool
	}{
		"fill upscale": {
			options: ResizeOptions{Width: 100, Height: 100, ResizeMode: ResizeModeFill},
			source: func(t *testing.T) afero.File {
				t.Helper()
				return newGrayJpeg(t, 50, 20)
			},
			matcher: sizeMatcher(100, 100),
		},
		"fill downscale": {
			options: ResizeOptions{Width: 100, Height: 100, ResizeMode: ResizeModeFill},
			source: func(t *testing.T) afero.File {
				t.Helper()
				return newGrayJpeg(t, 200, 150)
			},
			matcher: sizeMatcher(100, 100),
		},
		"fit upscale": {
			options: ResizeOptions{Width: 100, Height: 100, ResizeMode: ResizeModeFit},
			source: func(t *testing.T) afero.File {
				t.Helper()
				return newGrayJpeg(t, 50, 20)
			},
			matcher: sizeMatcher(50, 20),
		},
		"fit downscale": {
			options: ResizeOptions{Width: 100, Height: 100, ResizeMode: ResizeModeFit},
			source: func(t *testing.T) afero.File {
				t.Helper()
				return newGrayJpeg(t, 200, 150)
			},
			matcher: sizeMatcher(100, 75),
		},
		"keep original format": {
			options: ResizeOptions{Width: 100, Height: 100, Format: FormatPng},
			source: func(t *testing.T) afero.File {
				t.Helper()
				return newGrayPng(t, 200, 150)
			},
			matcher: formatMatcher(FormatPng),
		},
		"convert to jpeg": {
			options: ResizeOptions{Width: 100, Height: 100, Format: FormatJpeg},
			source: func(t *testing.T) afero.File {
				t.Helper()
				return newGrayJpeg(t, 200, 150)
			},
			matcher: formatMatcher(FormatJpeg),
		},
		"convert to png": {
			options: ResizeOptions{Width: 100, Height: 100, Format: FormatPng},
			source: func(t *testing.T) afero.File {
				t.Helper()
				return newGrayJpeg(t, 200, 150)
			},
			matcher: formatMatcher(FormatPng),
		},
		"convert to gif": {
			options: ResizeOptions{Width: 100, Height: 100, Format: FormatGif},
			source: func(t *testing.T) afero.File {
				t.Helper()
				return newGrayJpeg(t, 200, 150)
			},
			matcher: formatMatcher(FormatGif),
		},
		"convert to tiff": {
			options: ResizeOptions{Width: 100, Height: 100, Format: FormatTiff},
			source: func(t *testing.T) afero.File {
				t.Helper()
				return newGrayJpeg(t, 200, 150)
			},
			matcher: formatMatcher(FormatTiff),
		},
		"convert to bmp": {
			options: ResizeOptions{Width: 100, Height: 100, Format: FormatBmp},
			source: func(t *testing.T) afero.File {
				t.Helper()
				return newGrayJpeg(t, 200, 150)
			},
			matcher: formatMatcher(FormatBmp),
		},
		"convert to unknown": {
			options: ResizeOptions{Width: 100, Height: 100, Format: Format(-1)},
			source: func(t *testing.T) afero.File {
				t.Helper()
				return newGrayJpeg(t, 200, 150)
			},
			matcher: formatMatcher(FormatJpeg),
		},
		"resize png": {
			options: ResizeOptions{Width: 100, Height: 100, ResizeMode: ResizeModeFill},
			source: func(t *testing.T) afero.File {
				t.Helper()
				return newGrayPng(t, 200, 150)
			},
			matcher: sizeMatcher(100, 100),
		},
		"resize gif": {
			options: ResizeOptions{Width: 100, Height: 100, ResizeMode: ResizeModeFill},
			source: func(t *testing.T) afero.File {
				t.Helper()
				return newGrayGif(t, 200, 150)
			},
			matcher: sizeMatcher(100, 100),
		},
		"resize tiff": {
			options: ResizeOptions{Width: 100, Height: 100, ResizeMode: ResizeModeFill},
			source: func(t *testing.T) afero.File {
				t.Helper()
				return newGrayTiff(t, 200, 150)
			},
			matcher: sizeMatcher(100, 100),
		},
		"resize bmp": {
			options: ResizeOptions{Width: 100, Height: 100, ResizeMode: ResizeModeFill},
			source: func(t *testing.T) afero.File {
				t.Helper()
				return newGrayBmp(t, 200, 150)
			},
			matcher: sizeMatcher(100, 100),
		},
		"resize with high quality": {
			options: ResizeOptions{Width: 100, Height: 100, ResizeMode: ResizeModeFill, Quality: QualityHigh},
			source: func(t *testing.T) afero.File {
				t.Helper()
				return newGrayJpeg(t, 200, 150)
			},
			matcher: sizeMatcher(100, 100),
		},
		"resize with medium quality": {
			options: ResizeOptions{Width: 100, Height: 100, ResizeMode: ResizeModeFill, Quality: QualityMedium},
			source: func(t *testing.T) afero.File {
				t.Helper()
				return newGrayJpeg(t, 200, 150)
			},
			matcher: sizeMatcher(100, 100),
		},
		"resize with low quality": {
			options: ResizeOptions{Width: 100, Height: 100, ResizeMode: ResizeModeFill, Quality: QualityLow},
			source: func(t *testing.T) afero.File {
				t.Helper()
				return newGrayJpeg(t, 200, 150)
			},
			matcher: sizeMatcher(100, 100),
		},
		"resize with unknown quality": {
			options: ResizeOptions{Width: 100, Height: 100, ResizeMode: ResizeModeFill, Quality: Quality(-1)},
			source: func(t *testing.T) afero.File {
				t.Helper()
				return newGrayJpeg(t, 200, 150)
			},
			matcher: sizeMatcher(100, 100),
		},
		"get thumbnail from file with APP0 JFIF": {
			options: ResizeOptions{Width: 100, Height: 100, ResizeMode: ResizeModeFill, Quality: QualityLow},
			source: func(t *testing.T) afero.File {
				t.Helper()
				return newGrayJpegWithExifThumbnail(t, 640, 480, 125, 128, true)
			},
			matcher: sizeMatcher(125, 128),
		},
		"get thumbnail from file without APP0 JFIF": {
			options: ResizeOptions{Width: 100, Height: 100, ResizeMode: ResizeModeFill, Quality: QualityLow},
			source: func(t *testing.T) afero.File {
				t.Helper()
				return newGrayJpegWithExifThumbnail(t, 640, 480, 320, 240, false)
			},
			matcher: sizeMatcher(320, 240),
		},
		"resize from file without IFD1 thumbnail": {
			options: ResizeOptions{Width: 100, Height: 100, ResizeMode: ResizeModeFill, Quality: QualityLow},
			source: func(t *testing.T) afero.File {
				t.Helper()
				return newGrayJpegWithoutExifThumbnail(t, 200, 150, true)
			},
			matcher: sizeMatcher(100, 100),
		},
		"resize for higher quality levels": {
			options: ResizeOptions{Width: 100, Height: 100, ResizeMode: ResizeModeFill, Quality: QualityMedium},
			source: func(t *testing.T) afero.File {
				t.Helper()
				return newGrayJpegWithExifThumbnail(t, 640, 480, 125, 128, true)
			},
			matcher: sizeMatcher(100, 100),
		},
		"broken file": {
			options: ResizeOptions{Width: 100, Height: 100, ResizeMode: ResizeModeFit},
			source: func(t *testing.T) afero.File {
				t.Helper()
				fs := afero.NewMemMapFs()
				file, err := fs.Create("image.jpg")
				require.NoError(t, err)

				_, err = file.WriteString("this is not an image")
				require.NoError(t, err)

				return file
			},
			wantErr: true,
		},
	}

	for name, test := range testCases {
		t.Run(name, func(t *testing.T) {
			tmpDir := t.TempDir()
			svc := NewPreviewGenerator(1, tmpDir)
			source := test.source(t)
			defer source.Close()

			buf := &bytes.Buffer{}
			err := svc.Resize(context.Background(), source, buf, test.options)
			if (err != nil) != test.wantErr {
				t.Fatalf("GetMarketSpecs() error = %v, wantErr %v", err, test.wantErr)
			}
			if err != nil {
				return
			}
			test.matcher(t, buf)
		})
	}
}

func TestService_ResizeSafeDerivedTransparentPNG(t *testing.T) {
	img := image.NewNRGBA(image.Rect(0, 0, 32, 16))
	for y := 0; y < img.Bounds().Dy(); y++ {
		for x := 0; x < img.Bounds().Dx(); x++ {
			img.SetNRGBA(x, y, color.NRGBA{R: 255, A: 0})
		}
	}

	var source bytes.Buffer
	require.NoError(t, png.Encode(&source, img))

	var output bytes.Buffer
	svc := NewPreviewGenerator(1, t.TempDir())
	err := svc.Resize(context.Background(), bytes.NewReader(source.Bytes()), &output, ResizeOptions{
		Width:       16,
		Height:      16,
		Format:      FormatPng,
		ResizeMode:  ResizeModeFit,
		Quality:     QualityHigh,
		SafeDerived: true,
	})
	require.NoError(t, err)

	derived, format, err := image.Decode(bytes.NewReader(output.Bytes()))
	require.NoError(t, err)
	require.Equal(t, "jpeg", format)
	require.LessOrEqual(t, derived.Bounds().Dx(), 16)
	require.LessOrEqual(t, derived.Bounds().Dy(), 16)
	r, g, b, _ := derived.At(derived.Bounds().Min.X, derived.Bounds().Min.Y).RGBA()
	require.GreaterOrEqual(t, r, uint32(0xf000))
	require.GreaterOrEqual(t, g, uint32(0xf000))
	require.GreaterOrEqual(t, b, uint32(0xf000))
}

func TestService_ResizeSafeDerivedAnimatedGIFUsesFirstFrame(t *testing.T) {
	palette := color.Palette{
		color.RGBA{R: 255, A: 255},
		color.RGBA{B: 255, A: 255},
	}
	first := image.NewPaletted(image.Rect(0, 0, 40, 20), palette)
	second := image.NewPaletted(image.Rect(0, 0, 40, 20), palette)
	for i := range second.Pix {
		second.Pix[i] = 1
	}

	var source bytes.Buffer
	require.NoError(t, gif.EncodeAll(&source, &gif.GIF{
		Image: []*image.Paletted{first, second},
		Delay: []int{1, 1},
	}))

	var output bytes.Buffer
	svc := NewPreviewGenerator(1, t.TempDir())
	err := svc.Resize(context.Background(), bytes.NewReader(source.Bytes()), &output, ResizeOptions{
		Width:       10,
		Height:      10,
		Format:      FormatGif,
		ResizeMode:  ResizeModeFit,
		Quality:     QualityHigh,
		SafeDerived: true,
	})
	require.NoError(t, err)

	derived, format, err := image.Decode(bytes.NewReader(output.Bytes()))
	require.NoError(t, err)
	require.Equal(t, "jpeg", format)
	require.LessOrEqual(t, derived.Bounds().Dx(), 10)
	require.LessOrEqual(t, derived.Bounds().Dy(), 10)
	r, g, b, _ := derived.At(derived.Bounds().Min.X, derived.Bounds().Min.Y).RGBA()
	require.Greater(t, r, g)
	require.Greater(t, r, b)
}

func sizeMatcher(width, height int) func(t *testing.T, reader io.Reader) {
	return func(t *testing.T, reader io.Reader) {
		resizedImg, _, err := image.Decode(reader)
		require.NoError(t, err)

		require.Equal(t, width, resizedImg.Bounds().Dx())
		require.Equal(t, height, resizedImg.Bounds().Dy())
	}
}

func formatMatcher(format Format) func(t *testing.T, reader io.Reader) {
	return func(t *testing.T, reader io.Reader) {
		_, decodedFormat, err := image.DecodeConfig(reader)
		require.NoError(t, err)

		require.Equal(t, format.String(), decodedFormat)
	}
}

func newGrayJpeg(t *testing.T, width, height int) afero.File {
	fs := afero.NewMemMapFs()
	file, err := fs.Create("image.jpg")
	require.NoError(t, err)

	img := image.NewGray(image.Rect(0, 0, width, height))
	err = jpeg.Encode(file, img, &jpeg.Options{Quality: 90})
	require.NoError(t, err)

	_, err = file.Seek(0, io.SeekStart)
	require.NoError(t, err)

	return file
}

func newGrayJpegWithExifThumbnail(t *testing.T, width, height, thumbnailWidth, thumbnailHeight int, app0 bool) afero.File {
	t.Helper()

	thumbnail := encodeGrayJpeg(t, thumbnailWidth, thumbnailHeight)
	return newGrayJpegWithExif(t, width, height, app0, thumbnail)
}

func newGrayJpegWithoutExifThumbnail(t *testing.T, width, height int, app0 bool) afero.File {
	t.Helper()

	return newGrayJpegWithExif(t, width, height, app0, nil)
}

func newGrayJpegWithExif(t *testing.T, width, height int, app0 bool, thumbnail []byte) afero.File {
	t.Helper()

	mainImage := encodeGrayJpeg(t, width, height)
	require.GreaterOrEqual(t, len(mainImage), 2)
	require.Equal(t, []byte{0xff, 0xd8}, mainImage[:2])

	data := make([]byte, 0, len(mainImage)+len(thumbnail)+64)
	data = append(data, 0xff, 0xd8)
	if app0 {
		data = append(data,
			0xff, 0xe0, 0x00, 0x10,
			'J', 'F', 'I', 'F', 0x00,
			0x01, 0x01, 0x00,
			0x00, 0x01, 0x00, 0x01,
			0x00, 0x00,
		)
	}
	data = append(data, buildExifAPP1(t, thumbnail)...)
	data = append(data, mainImage[2:]...)

	return newTemporaryJpeg(t, data)
}

func encodeGrayJpeg(t *testing.T, width, height int) []byte {
	t.Helper()

	var data bytes.Buffer
	img := image.NewGray(image.Rect(0, 0, width, height))
	require.NoError(t, jpeg.Encode(&data, img, &jpeg.Options{Quality: 90}))
	return data.Bytes()
}

func buildExifAPP1(t *testing.T, thumbnail []byte) []byte {
	t.Helper()

	const (
		ifd0Offset      = 8
		ifd1Offset      = 14
		thumbnailOffset = 44
	)
	tiffSize := ifd1Offset
	if len(thumbnail) > 0 {
		tiffSize = thumbnailOffset + len(thumbnail)
	}
	tiff := make([]byte, tiffSize)
	copy(tiff[0:2], "II")
	binary.LittleEndian.PutUint16(tiff[2:4], 42)
	binary.LittleEndian.PutUint32(tiff[4:8], ifd0Offset)

	if len(thumbnail) > 0 {
		binary.LittleEndian.PutUint32(tiff[10:14], ifd1Offset)
		binary.LittleEndian.PutUint16(tiff[14:16], 2)

		jpegOffsetEntry := tiff[16:28]
		binary.LittleEndian.PutUint16(jpegOffsetEntry[0:2], 0x0201)
		binary.LittleEndian.PutUint16(jpegOffsetEntry[2:4], 4)
		binary.LittleEndian.PutUint32(jpegOffsetEntry[4:8], 1)
		binary.LittleEndian.PutUint32(jpegOffsetEntry[8:12], thumbnailOffset)

		jpegLengthEntry := tiff[28:40]
		binary.LittleEndian.PutUint16(jpegLengthEntry[0:2], 0x0202)
		binary.LittleEndian.PutUint16(jpegLengthEntry[2:4], 4)
		binary.LittleEndian.PutUint32(jpegLengthEntry[4:8], 1)
		binary.LittleEndian.PutUint32(jpegLengthEntry[8:12], uint32(len(thumbnail)))

		copy(tiff[thumbnailOffset:], thumbnail)
	}

	payload := make([]byte, 6+len(tiff))
	copy(payload, "Exif\x00\x00")
	copy(payload[6:], tiff)
	require.LessOrEqual(t, len(payload)+2, int(^uint16(0)))

	segment := make([]byte, 4+len(payload))
	segment[0], segment[1] = 0xff, 0xe1
	binary.BigEndian.PutUint16(segment[2:4], uint16(len(payload)+2))
	copy(segment[4:], payload)
	return segment
}

func newTemporaryJpeg(t *testing.T, data []byte) afero.File {
	t.Helper()

	file, err := os.CreateTemp(t.TempDir(), "preview-*.jpg")
	require.NoError(t, err)
	t.Cleanup(func() { _ = file.Close() })

	written, err := file.Write(data)
	require.NoError(t, err)
	require.Equal(t, len(data), written)
	_, err = file.Seek(0, io.SeekStart)
	require.NoError(t, err)
	return file
}

func newTemporaryGrayJpegPath(t *testing.T, width, height int) string {
	t.Helper()

	file := newTemporaryJpeg(t, encodeGrayJpeg(t, width, height))
	path := file.Name()
	require.NoError(t, file.Close())
	return path
}

func newGrayPng(t *testing.T, width, height int) afero.File {
	fs := afero.NewMemMapFs()
	file, err := fs.Create("image.png")
	require.NoError(t, err)

	img := image.NewGray(image.Rect(0, 0, width, height))
	err = png.Encode(file, img)
	require.NoError(t, err)

	_, err = file.Seek(0, io.SeekStart)
	require.NoError(t, err)

	return file
}

func newGrayGif(t *testing.T, width, height int) afero.File {
	fs := afero.NewMemMapFs()
	file, err := fs.Create("image.gif")
	require.NoError(t, err)

	img := image.NewGray(image.Rect(0, 0, width, height))
	err = gif.Encode(file, img, nil)
	require.NoError(t, err)

	_, err = file.Seek(0, io.SeekStart)
	require.NoError(t, err)

	return file
}

func newGrayTiff(t *testing.T, width, height int) afero.File {
	fs := afero.NewMemMapFs()
	file, err := fs.Create("image.tiff")
	require.NoError(t, err)

	img := image.NewGray(image.Rect(0, 0, width, height))
	err = tiff.Encode(file, img, nil)
	require.NoError(t, err)

	_, err = file.Seek(0, io.SeekStart)
	require.NoError(t, err)

	return file
}

func newGrayBmp(t *testing.T, width, height int) afero.File {
	fs := afero.NewMemMapFs()
	file, err := fs.Create("image.bmp")
	require.NoError(t, err)

	img := image.NewGray(image.Rect(0, 0, width, height))
	err = bmp.Encode(file, img)
	require.NoError(t, err)

	_, err = file.Seek(0, io.SeekStart)
	require.NoError(t, err)

	return file
}

func TestService_FormatFromExtension(t *testing.T) {
	testCases := map[string]struct {
		ext     string
		want    Format
		wantErr error
	}{
		"jpg": {
			ext:  ".jpg",
			want: FormatJpeg,
		},
		"jpeg": {
			ext:  ".jpeg",
			want: FormatJpeg,
		},
		"png": {
			ext:  ".png",
			want: FormatPng,
		},
		"gif": {
			ext:  ".gif",
			want: FormatGif,
		},
		"tiff": {
			ext:  ".tiff",
			want: FormatTiff,
		},
		"tif": {
			ext:  ".tif",
			want: FormatTiff,
		},
		"bmp": {
			ext:  ".bmp",
			want: FormatBmp,
		},
		"heic": {
			ext:  ".heic",
			want: FormatHeic,
		},
		"heif": {
			ext:  ".heif",
			want: FormatHeic,
		},
		"webp": {
			ext:  ".webp",
			want: FormatWebp,
		},
		"unknown": {
			ext:     ".mov",
			wantErr: ErrUnsupportedFormat,
		},
	}

	for name, test := range testCases {
		t.Run(name, func(t *testing.T) {
			tmpDir := t.TempDir()
			svc := NewPreviewGenerator(1, tmpDir)
			got, err := svc.FormatFromExtension(test.ext)
			require.Truef(t, errors.Is(err, test.wantErr), "error = %v, wantErr %v", err, test.wantErr)
			if err != nil {
				return
			}
			require.Equal(t, test.want, got)
		})
	}
}

func TestCacheKeyConsistency(t *testing.T) {
	// Test that folder previews and direct file previews use the same cache key
	// when the folder preview is based on a child file

	// Test direct file preview
	cacheKey1 := CacheKey("testmd5hash123", "small", 0)

	// Test folder preview with same child MD5
	cacheKey2 := CacheKey("testmd5hash123", "small", 0)

	// Both should produce the same cache key
	require.Equal(t, cacheKey1, cacheKey2, "Folder preview and direct file preview should use the same cache key")

	// Test with different seek percentages
	cacheKey3 := CacheKey("testmd5hash123", "small", 25)
	cacheKey4 := CacheKey("testmd5hash123", "small", 25)

	require.Equal(t, cacheKey3, cacheKey4, "Cache keys should be consistent for same parameters")
	require.NotEqual(t, cacheKey1, cacheKey3, "Different seek percentages should produce different cache keys")
}

// TestResize_ConcurrencyLimit verifies that imageSem works for basic concurrency control
func TestResize_ConcurrencyLimit(t *testing.T) {
	tmpDir := t.TempDir()
	svc := NewPreviewGenerator(2, tmpDir)
	require.NotNil(t, svc.imageSem, "imageSem must be non-nil to test concurrency limit")

	// Simple smoke test - just verify Resize works with the semaphore
	source := newGrayJpeg(t, 100, 100)
	defer source.Close()
	out := &bytes.Buffer{}
	err := svc.Resize(context.Background(), source, out, ResizeOptions{Width: 50, Height: 50})
	require.NoError(t, err)
	require.Greater(t, out.Len(), 0)
}

// TestResize_ConcurrencyLimit_NoFFmpeg verifies that imageSem works correctly
func TestResize_ConcurrencyLimit_NoFFmpeg(t *testing.T) {
	tmpDir := t.TempDir()
	svc := NewPreviewGenerator(1, tmpDir)
	require.NotNil(t, svc.imageSem, "imageSem should exist for concurrency control")

	source := newGrayJpeg(t, 100, 100)
	defer source.Close()
	out := &bytes.Buffer{}
	err := svc.Resize(context.Background(), source, out, ResizeOptions{Width: 50, Height: 50})
	require.NoError(t, err)
	require.Greater(t, out.Len(), 0)
}

// TestCreatePreviewFromReader_UsesConcurrencyLimit verifies that CreatePreviewFromReader
// goes through Resize and thus respects the imageSem semaphore (smoke test).
func TestCreatePreviewFromReader_UsesConcurrencyLimit(t *testing.T) {
	tmpDir := t.TempDir()
	svc := NewPreviewGenerator(2, tmpDir)

	source := newGrayJpeg(t, 200, 200)
	defer source.Close()
	data, err := io.ReadAll(source)
	require.NoError(t, err)

	// Get options for small preview
	options, err := getPreviewOptions("small")
	require.NoError(t, err)

	// Create preview from reader
	out, err := svc.CreatePreview(context.Background(), bytes.NewReader(data), int64(len(data)), options)
	require.NoError(t, err)
	require.NotEmpty(t, out)

	// Same via another call for parity
	out2, err := svc.CreatePreview(context.Background(), bytes.NewReader(data), int64(len(data)), options)
	require.NoError(t, err)
	require.Equal(t, out, out2)
}

func TestImageFitsPreviewSize(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		width       int
		height      int
		previewSize string
		want        bool
	}{
		{name: "fits xlarge", width: 800, height: 600, previewSize: "xlarge", want: true},
		{name: "exceeds xlarge width", width: 1200, height: 600, previewSize: "xlarge", want: false},
		{name: "fits large", width: 640, height: 480, previewSize: "large", want: true},
		{name: "fits small", width: 256, height: 200, previewSize: "small", want: true},
		{name: "exceeds small height", width: 200, height: 300, previewSize: "small", want: false},
		{name: "original always fits", width: 5000, height: 5000, previewSize: "original", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.want, ImageFitsPreviewSize(tt.width, tt.height, tt.previewSize))
		})
	}
}

func TestReadImageFileDimensions(t *testing.T) {
	t.Parallel()

	width, height, err := ReadImageFileDimensions(newTemporaryGrayJpegPath(t, 125, 128))
	require.NoError(t, err)
	require.Greater(t, width, 0)
	require.Greater(t, height, 0)
}
