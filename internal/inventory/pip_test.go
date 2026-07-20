package inventory

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPipCollector_Collect(t *testing.T) {
	collector := &PipCollector{}
	components, err := collector.Collect(context.Background(), "../../testdata/requirements.txt.fixture")
	require.NoError(t, err)

	assert.Len(t, components, 4)

	names := make(map[string]string)
	for _, c := range components {
		names[c.Name] = c.Version
		assert.Equal(t, "pip", c.Type)
	}

	assert.Equal(t, "2.31.0", names["requests"])
	assert.Equal(t, "", names["flask"]) // >= is a constraint, not a known version
	assert.Equal(t, "1.24.3", names["numpy"])
	assert.Equal(t, "", names["django"]) // >= is a constraint, not a known version
}

func TestPipCollector_VersionlessPURL(t *testing.T) {
	name, version := parsePipRequirement("simple-package")
	assert.Equal(t, "simple-package", name)
	assert.Equal(t, "", version)

	purl := fmt.Sprintf("pkg:pypi/%s", name)
	if version != "" {
		purl += "@" + version
	}
	assert.Equal(t, "pkg:pypi/simple-package", purl, "versionless PURL should not have trailing @")
}

func TestParsePipRequirement(t *testing.T) {
	tests := []struct {
		line    string
		name    string
		version string
	}{
		// Exact and compatible-release specifiers denote a known version.
		{"requests==2.31.0", "requests", "2.31.0"},
		{"numpy==1.24.3 ; python_version >= '3.8'", "numpy", "1.24.3"},
		{"wheel~=0.40", "wheel", "0.40"},
		{"pkg~=0.40,<0.41", "pkg", "0.40"},

		// Constraints (>=, <=, !=, >, <) describe an unknown installed version;
		// reporting a version would risk both false negatives and false positives.
		{"flask>=2.3.0", "flask", ""},
		{"django[argon2]>=4.2,<5.0", "django", ""},
		{"lib!=1.5", "lib", ""},
		{"pkg>1.0", "pkg", ""},
		{"pkg<2.0", "pkg", ""},

		// No specifier — name only.
		{"simple-package", "simple-package", ""},
	}
	for _, tt := range tests {
		t.Run(tt.line, func(t *testing.T) {
			name, version := parsePipRequirement(tt.line)
			assert.Equal(t, tt.name, name)
			assert.Equal(t, tt.version, version)
		})
	}
}
