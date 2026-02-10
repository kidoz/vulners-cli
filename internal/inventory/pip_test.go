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
	assert.Equal(t, "2.3.0", names["flask"])
	assert.Equal(t, "1.24.3", names["numpy"])
	assert.Equal(t, "4.2", names["django"])
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
		{"requests==2.31.0", "requests", "2.31.0"},
		{"flask>=2.3.0", "flask", "2.3.0"},
		{"django[argon2]>=4.2,<5.0", "django", "4.2"},
		{"numpy==1.24.3 ; python_version >= '3.8'", "numpy", "1.24.3"},
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
