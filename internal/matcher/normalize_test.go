package matcher

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/kidoz/vulners-cli/internal/model"
)

func TestNormalizeComponent(t *testing.T) {
	tests := []struct {
		name  string
		input model.Component
		want  model.Component
	}{
		{
			name:  "lowercase name and type",
			input: model.Component{Name: "Gorilla/Mux", Type: "Go-Module", Version: "v1.8.0"},
			want:  model.Component{Name: "gorilla/mux", Type: "go-module", Version: "v1.8.0"},
		},
		{
			name:  "already lowercase",
			input: model.Component{Name: "express", Type: "library", Version: "4.17.1"},
			want:  model.Component{Name: "express", Type: "library", Version: "4.17.1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeComponent(tt.input)
			assert.Equal(t, tt.want.Name, got.Name)
			assert.Equal(t, tt.want.Type, got.Type)
			assert.Equal(t, tt.want.Version, got.Version)
		})
	}
}
