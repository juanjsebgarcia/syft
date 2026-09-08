package cli

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/format/cyclonedxjson"
	"github.com/anchore/syft/syft/format/cyclonedxxml"
	"github.com/anchore/syft/syft/format/spdxjson"
	"github.com/anchore/syft/syft/format/spdxtagvalue"
	"github.com/anchore/syft/syft/sbom"
)

func TestConvertCmd(t *testing.T) {
	assertions := []traitAssertion{
		assertInOutput("musl-utils"),
		assertSuccessfulReturnCode,
	}

	tests := []struct {
		from   string
		to     string
		expect sbom.FormatEncoder
	}{
		{from: "syft-json", to: "spdx-tag-value", expect: mustEncoder(spdxtagvalue.NewFormatEncoderWithConfig(spdxtagvalue.DefaultEncoderConfig()))},
		{from: "syft-json", to: "spdx-json", expect: mustEncoder(spdxjson.NewFormatEncoderWithConfig(spdxjson.DefaultEncoderConfig()))},
		{from: "syft-json", to: "spdx-json@3.0", expect: mustEncoder(spdxjson.NewFormatEncoderWithConfig(spdxjson.DefaultEncoderConfig()))},
		{from: "syft-json", to: "cyclonedx-json", expect: mustEncoder(cyclonedxjson.NewFormatEncoderWithConfig(cyclonedxjson.DefaultEncoderConfig()))},
		{from: "syft-json", to: "cyclonedx-xml", expect: mustEncoder(cyclonedxxml.NewFormatEncoderWithConfig(cyclonedxxml.DefaultEncoderConfig()))},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("from %s to %s", test.from, test.to), func(t *testing.T) {
			sbomArgs := []string{"dir:./testdata/image-pkg-coverage", "-o", test.from}
			cmd, stdout, stderr := runSyft(t, nil, sbomArgs...)
			if cmd.ProcessState.ExitCode() != 0 {
				t.Log("STDOUT:\n", stdout)
				t.Log("STDERR:\n", stderr)
				t.Log("COMMAND:", strings.Join(cmd.Args, " "))
				t.Fatalf("failure executing syft creating an sbom")
				return
			}

			convertArgs := []string{"convert", "-", "-o", test.to}
			cmd = getSyftCommand(t, convertArgs...)

			cmd.Stdin = strings.NewReader(stdout)
			stdout, stderr = runCommandObj(t, cmd, nil, false)

			for _, traitFn := range assertions {
				traitFn(t, stdout, stderr, cmd.ProcessState.ExitCode())
			}
			logOutputOnFailure(t, cmd, stdout, stderr)

			// let's make sure the output is valid relative to the expected format
			foundID, _ := format.Identify(strings.NewReader(stdout))
			require.Equal(t, test.expect.ID(), foundID)

		})
	}
}

func TestConvertCmd_PassthroughIfSameFormat(t *testing.T) {
	sbomArgs := []string{"dir:./testdata/image-pkg-coverage", "-o", "cyclonedx-json"}
	cmd, input, stderr := runSyft(t, nil, sbomArgs...)
	if cmd.ProcessState.ExitCode() != 0 {
		t.Log("STDOUT:\n", input)
		t.Log("STDERR:\n", stderr)
		t.Log("COMMAND:", strings.Join(cmd.Args, " "))
		t.Fatalf("failure executing syft creating an sbom")
		return
	}

	inputID, inputVersion := format.Identify(strings.NewReader(input))
	require.Equal(t, cyclonedxjson.ID, inputID)
	require.NotEmpty(t, inputVersion)

	tests := []struct {
		name          string
		to            string
		wantUnchanged bool
		wantID        sbom.FormatID
		wantVersion   string
	}{
		{
			name:          "same format and version is passed through unchanged",
			to:            "cyclonedx-json@" + inputVersion,
			wantUnchanged: true,
			wantID:        cyclonedxjson.ID,
			wantVersion:   inputVersion,
		},
		{
			name:        "different version is converted",
			to:          "cyclonedx-json@1.4",
			wantID:      cyclonedxjson.ID,
			wantVersion: "1.4",
		},
		{
			name:        "different format is converted",
			to:          "spdx-json",
			wantID:      spdxjson.ID,
			wantVersion: mustEncoder(spdxjson.NewFormatEncoderWithConfig(spdxjson.DefaultEncoderConfig())).Version(),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cmd := getSyftCommand(t, "convert", "-", "-o", test.to, "--passthrough-if-same-format")
			cmd.Stdin = strings.NewReader(input)
			stdout, stderr := runCommandObj(t, cmd, nil, false)

			assertSuccessfulReturnCode(t, stdout, stderr, cmd.ProcessState.ExitCode())
			logOutputOnFailure(t, cmd, stdout, stderr)

			foundID, foundVersion := format.Identify(strings.NewReader(stdout))
			require.Equal(t, test.wantID, foundID)
			require.Equal(t, test.wantVersion, foundVersion)

			if test.wantUnchanged {
				require.Equal(t, strings.TrimSpace(input), strings.TrimSpace(stdout))
			} else {
				require.NotEqual(t, strings.TrimSpace(input), strings.TrimSpace(stdout))
			}
		})
	}
}

func mustEncoder(enc sbom.FormatEncoder, err error) sbom.FormatEncoder {
	if err != nil {
		panic(err)
	}
	return enc
}
