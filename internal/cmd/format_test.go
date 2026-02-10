package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateNonScanFormat(t *testing.T) {
	tests := []struct {
		name    string
		format  string
		wantErr bool
	}{
		{name: "json allowed", format: "json", wantErr: false},
		{name: "table allowed", format: "table", wantErr: false},
		{name: "sarif rejected", format: "sarif", wantErr: true},
		{name: "html rejected", format: "html", wantErr: true},
		{name: "cyclonedx rejected", format: "cyclonedx", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateNonScanFormat(tt.format)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "only supported for scan commands")
			} else {
				require.NoError(t, err)
			}
		})
	}
}
