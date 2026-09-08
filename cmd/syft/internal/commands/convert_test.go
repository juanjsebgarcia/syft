package commands

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/cmd/syft/internal/options"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/format/cyclonedxjson"
	"github.com/anchore/syft/syft/format/spdxjson"
	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

func convertTestSBOM() sbom.SBOM {
	catalog := pkg.NewCollection()
	catalog.Add(pkg.Package{
		Name:    "musl-utils",
		Version: "1.2.3-r4",
		Type:    pkg.ApkPkg,
		FoundBy: "apk-db-cataloger",
		Locations: file.NewLocationSet(
			file.NewLocation("/lib/apk/db/installed"),
		),
		PURL: "pkg:apk/alpine/musl-utils@1.2.3-r4",
	})

	return sbom.SBOM{
		Artifacts: sbom.Artifacts{
			Packages: catalog,
		},
		Source: source.Description{
			ID:      "some-id",
			Name:    "some-dir",
			Version: "latest",
			Metadata: source.DirectoryMetadata{
				Path: "/some/path",
			},
		},
		Descriptor: sbom.Descriptor{
			Name:    "syft",
			Version: "v0.0.0-test",
		},
	}
}

func mustConvertEncoder(enc sbom.FormatEncoder, err error) sbom.FormatEncoder {
	if err != nil {
		panic(err)
	}
	return enc
}

func encodeConvertTestSBOM(t *testing.T, enc sbom.FormatEncoder) []byte {
	buf := &bytes.Buffer{}
	require.NoError(t, enc.Encode(buf, convertTestSBOM()))
	return buf.Bytes()
}

func Test_partitionOutputsBySourceFormat(t *testing.T) {
	cdxEncoder := mustConvertEncoder(cyclonedxjson.NewFormatEncoderWithConfig(cyclonedxjson.DefaultEncoderConfig()))
	cdxVersion := cdxEncoder.Version()
	cdxContent := encodeConvertTestSBOM(t, cdxEncoder)

	syftContent := encodeConvertTestSBOM(t, mustConvertEncoder(syftjson.NewFormatEncoderWithConfig(syftjson.DefaultEncoderConfig())))

	tests := []struct {
		name          string
		content       []byte
		outputs       []string
		wantUnchanged []string
		wantToConvert []string
	}{
		{
			name:          "bare format name matches the default version",
			content:       cdxContent,
			outputs:       []string{"cyclonedx-json"},
			wantUnchanged: []string{"cyclonedx-json"},
		},
		{
			name:          "explicit version and file path match",
			content:       cdxContent,
			outputs:       []string{"cyclonedx-json@" + cdxVersion + "=out/some.cdx.json"},
			wantUnchanged: []string{"cyclonedx-json@" + cdxVersion + "=out/some.cdx.json"},
		},
		{
			name:          "different version requires conversion",
			content:       cdxContent,
			outputs:       []string{"cyclonedx-json@1.4"},
			wantToConvert: []string{"cyclonedx-json@1.4"},
		},
		{
			name:          "different format requires conversion",
			content:       cdxContent,
			outputs:       []string{"spdx-json"},
			wantToConvert: []string{"spdx-json"},
		},
		{
			name:          "unknown format is left for the writer to report",
			content:       cdxContent,
			outputs:       []string{"bogus"},
			wantToConvert: []string{"bogus"},
		},
		{
			name:          "mixed outputs are partitioned",
			content:       cdxContent,
			outputs:       []string{"cyclonedx-json=a.json", "spdx-json=b.json", "cyclonedx-xml"},
			wantUnchanged: []string{"cyclonedx-json=a.json"},
			wantToConvert: []string{"spdx-json=b.json", "cyclonedx-xml"},
		},
		{
			name:          "unidentifiable content is left for the decoder to report",
			content:       []byte("definitely not an sbom"),
			outputs:       []string{"cyclonedx-json"},
			wantToConvert: []string{"cyclonedx-json"},
		},
		{
			name:          "syft-json matches on the current schema version",
			content:       syftContent,
			outputs:       []string{"syft-json", "json"},
			wantUnchanged: []string{"syft-json", "json"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := options.DefaultOutput()
			output.Outputs = tt.outputs

			unchanged, toConvert, err := partitionOutputsBySourceFormat(output, tt.content)
			require.NoError(t, err)
			assert.Equal(t, tt.wantUnchanged, unchanged)
			assert.Equal(t, tt.wantToConvert, toConvert)
		})
	}
}

func Test_RunConvert_passthroughIfSameFormat(t *testing.T) {
	cdxContent := encodeConvertTestSBOM(t, mustConvertEncoder(cyclonedxjson.NewFormatEncoderWithConfig(cyclonedxjson.DefaultEncoderConfig())))

	newOpts := func(passthrough bool, outputs ...string) *ConvertOptions {
		opts := &ConvertOptions{
			Output: options.DefaultOutput(),
			Convert: options.Convert{
				PassthroughIfSameFormat: passthrough,
			},
		}
		opts.Outputs = outputs
		return opts
	}

	writeInput := func(t *testing.T) string {
		input := filepath.Join(t.TempDir(), "input.cdx.json")
		require.NoError(t, os.WriteFile(input, cdxContent, 0600))
		return input
	}

	t.Run("matching output is copied unchanged while others are converted", func(t *testing.T) {
		dir := t.TempDir()
		cdxOut := filepath.Join(dir, "out.cdx.json")
		spdxOut := filepath.Join(dir, "out.spdx.json")

		opts := newOpts(true, "cyclonedx-json="+cdxOut, "spdx-json="+spdxOut)
		require.NoError(t, RunConvert(opts, writeInput(t)))

		got, err := os.ReadFile(cdxOut)
		require.NoError(t, err)
		assert.Equal(t, cdxContent, got)

		spdx, err := os.ReadFile(spdxOut)
		require.NoError(t, err)
		id, _ := format.Identify(bytes.NewReader(spdx))
		assert.Equal(t, spdxjson.ID, id)
	})

	t.Run("without the option the matching output is re-encoded", func(t *testing.T) {
		cdxOut := filepath.Join(t.TempDir(), "out.cdx.json")

		opts := newOpts(false, "cyclonedx-json="+cdxOut)
		require.NoError(t, RunConvert(opts, writeInput(t)))

		got, err := os.ReadFile(cdxOut)
		require.NoError(t, err)
		id, _ := format.Identify(bytes.NewReader(got))
		assert.Equal(t, cyclonedxjson.ID, id)
		// a fresh serial number is minted on every encode, so a round trip never reproduces the input
		assert.NotEqual(t, cdxContent, got)
	})

	t.Run("a different version is still converted", func(t *testing.T) {
		cdxOut := filepath.Join(t.TempDir(), "out.cdx.json")

		opts := newOpts(true, "cyclonedx-json@1.4="+cdxOut)
		require.NoError(t, RunConvert(opts, writeInput(t)))

		got, err := os.ReadFile(cdxOut)
		require.NoError(t, err)
		id, version := format.Identify(bytes.NewReader(got))
		assert.Equal(t, cyclonedxjson.ID, id)
		assert.Equal(t, "1.4", version)
		assert.NotEqual(t, cdxContent, got)
	})

	t.Run("the deprecated --file path is honored", func(t *testing.T) {
		cdxOut := filepath.Join(t.TempDir(), "out.cdx.json")

		opts := newOpts(true, "cyclonedx-json")
		opts.LegacyFile = cdxOut
		require.NoError(t, RunConvert(opts, writeInput(t)))

		got, err := os.ReadFile(cdxOut)
		require.NoError(t, err)
		assert.Equal(t, cdxContent, got)
	})

	t.Run("an invalid output fails before anything is written", func(t *testing.T) {
		cdxOut := filepath.Join(t.TempDir(), "out.cdx.json")

		opts := newOpts(true, "cyclonedx-json="+cdxOut, "bogus")
		require.Error(t, RunConvert(opts, writeInput(t)))

		assert.NoFileExists(t, cdxOut)
	})
}
