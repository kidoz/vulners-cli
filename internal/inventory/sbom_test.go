package inventory

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSBOMCollector_CycloneDX(t *testing.T) {
	collector := &SBOMCollector{Format: "cyclonedx"}
	components, err := collector.Collect(context.Background(), "../../testdata/cyclonedx.json")
	require.NoError(t, err)

	assert.Len(t, components, 2)
	assert.Equal(t, "lodash", components[0].Name)
	assert.Equal(t, "4.17.19", components[0].Version)
	assert.Equal(t, "pkg:npm/lodash@4.17.19", components[0].PURL)
}

func TestSBOMCollector_SPDX(t *testing.T) {
	collector := &SBOMCollector{Format: "spdx"}
	components, err := collector.Collect(context.Background(), "../../testdata/spdx.json")
	require.NoError(t, err)

	require.Len(t, components, 3)

	assert.Equal(t, "lodash", components[0].Name)
	assert.Equal(t, "4.17.21", components[0].Version)
	assert.Equal(t, "pkg:npm/lodash@4.17.21", components[0].PURL)

	assert.Equal(t, "express", components[1].Name)
	assert.Equal(t, "4.18.2", components[1].Version)
	assert.Equal(t, "pkg:npm/express@4.18.2", components[1].PURL)

	assert.Equal(t, "internal-lib", components[2].Name)
	assert.Equal(t, "1.0.0", components[2].Version)
	assert.Empty(t, components[2].PURL)
}

func TestSBOMCollector_UnsupportedFormat(t *testing.T) {
	collector := &SBOMCollector{Format: "unknown"}
	_, err := collector.Collect(context.Background(), "../../testdata/cyclonedx.json")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported SBOM format")
}
