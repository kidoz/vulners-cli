package cmd

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateSchema_ScanOutput(t *testing.T) {
	schema, err := generateSchema("scan")
	require.NoError(t, err)
	require.NotNil(t, schema)

	data, err := json.Marshal(schema)
	require.NoError(t, err)
	require.True(t, json.Valid(data))

	var m map[string]any
	require.NoError(t, json.Unmarshal(data, &m))

	// Schema should contain standard JSON Schema keys.
	// Properties may be at top level or within $defs depending on library version.
	hasProps := m["properties"] != nil
	hasDefs := m["$defs"] != nil
	hasRef := m["$ref"] != nil
	assert.True(t, hasProps || hasDefs || hasRef,
		"schema should have properties, $defs, or $ref; got keys: %v", keys(m))
}

func TestGenerateSchema_DoctorOutput(t *testing.T) {
	schema, err := generateSchema("doctor")
	require.NoError(t, err)

	data, err := json.Marshal(schema)
	require.NoError(t, err)

	var m map[string]any
	require.NoError(t, json.Unmarshal(data, &m))

	// Doctor wraps in IntelOutput envelope — should have schema structure.
	hasProps := m["properties"] != nil
	hasDefs := m["$defs"] != nil
	hasRef := m["$ref"] != nil
	assert.True(t, hasProps || hasDefs || hasRef,
		"schema should have properties, $defs, or $ref")
}

func TestGenerateSchema_UnknownCommand(t *testing.T) {
	_, err := generateSchema("nonexistent")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown command")
}

func TestListSchemaCommands(t *testing.T) {
	cmds := listSchemaCommands()
	require.True(t, len(cmds) > 10, "should list many commands, got %d", len(cmds))

	// Verify sorted order.
	for i := 1; i < len(cmds); i++ {
		assert.True(t, cmds[i-1] < cmds[i], "commands should be sorted: %s < %s", cmds[i-1], cmds[i])
	}

	// Verify key commands are present.
	found := make(map[string]bool)
	for _, c := range cmds {
		found[c] = true
	}
	assert.True(t, found["scan"])
	assert.True(t, found["doctor"])
	assert.True(t, found["search"])
	assert.True(t, found["vscan-project-list"])
}

func TestGenerateSchema_AllCommandsSucceed(t *testing.T) {
	for _, name := range listSchemaCommands() {
		t.Run(name, func(t *testing.T) {
			schema, err := generateSchema(name)
			require.NoError(t, err)
			require.NotNil(t, schema)

			// Verify it serializes to valid JSON.
			data, err := json.Marshal(schema)
			require.NoError(t, err)
			assert.True(t, json.Valid(data), "schema JSON should be valid")
		})
	}
}

func keys(m map[string]any) []string {
	var ks []string
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}
