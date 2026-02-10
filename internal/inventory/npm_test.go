package inventory

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNPMCollector_ScopedPURL(t *testing.T) {
	collector := &NPMCollector{}
	components, err := collector.Collect(context.Background(), "../../testdata/package-lock.json.fixture")
	require.NoError(t, err)

	for _, c := range components {
		if c.Name == "@babel/core" {
			assert.Equal(t, "pkg:npm/%40babel/core@7.23.0", c.PURL)
			return
		}
	}
	t.Fatal("@babel/core not found in components")
}

func TestNPMCollector_DeterministicOrder(t *testing.T) {
	collector := &NPMCollector{}

	first, err := collector.Collect(context.Background(), "../../testdata/package-lock.json.fixture")
	require.NoError(t, err)

	second, err := collector.Collect(context.Background(), "../../testdata/package-lock.json.fixture")
	require.NoError(t, err)

	require.Equal(t, len(first), len(second))
	for i := range first {
		assert.Equal(t, first[i].Name, second[i].Name, "order mismatch at index %d", i)
	}
}

func TestNPMCollector_Collect(t *testing.T) {
	collector := &NPMCollector{}
	components, err := collector.Collect(context.Background(), "../../testdata/package-lock.json.fixture")
	require.NoError(t, err)

	assert.Len(t, components, 4)

	names := make(map[string]string)
	for _, c := range components {
		names[c.Name] = c.Version
		assert.Equal(t, "npm", c.Type)
	}

	assert.Equal(t, "4.17.21", names["lodash"])
	assert.Equal(t, "4.18.2", names["express"])
	assert.Equal(t, "7.23.0", names["@babel/core"])
	// Nested dep: node_modules/express/node_modules/qs → name "qs"
	assert.Equal(t, "6.11.0", names["qs"])
}
