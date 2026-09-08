package options

import (
	"github.com/anchore/clio"
)

var _ interface {
	clio.FlagAdder
	clio.FieldDescriber
} = (*Convert)(nil)

// Convert holds the options specific to the convert command.
type Convert struct {
	PassthroughIfSameFormat bool `yaml:"passthrough-if-same-format" json:"passthrough-if-same-format" mapstructure:"passthrough-if-same-format"`
}

func DefaultConvert() Convert {
	return Convert{
		PassthroughIfSameFormat: false,
	}
}

func (o *Convert) AddFlags(flags clio.FlagSet) {
	flags.BoolVarP(&o.PassthroughIfSameFormat, "passthrough-if-same-format", "",
		"write the input SBOM unchanged when it is already in the requested output format and version (format options such as pretty printing are not applied)")
}

func (o *Convert) DescribeFields(descriptions clio.FieldDescriptionSet) {
	descriptions.Add(&o.PassthroughIfSameFormat, `when the input SBOM is already in the requested output format and version, write it out unchanged instead of decoding and re-encoding it.
Note: output written this way is a byte-for-byte copy of the input, so format options (such as 'format.pretty' or 'format.json.legacy') are not applied to it.
Note: syft-json documents only match when their schema version is identical to the schema version this version of syft produces.
Note: to keep memory use minimal on large documents, give the input as a file path (or a shell redirect) and write the output with '-o <format>=<path>'. Piped input, or output to STDOUT, requires the whole document to be held in memory.`)
}
