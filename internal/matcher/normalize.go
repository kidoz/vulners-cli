package matcher

import (
	"strings"

	"github.com/kidoz/vulners-cli/internal/model"
)

// NormalizeComponent prepares a component for vulnerability matching.
func NormalizeComponent(c model.Component) model.Component {
	c.Name = strings.ToLower(strings.TrimSpace(c.Name))
	c.Version = strings.TrimSpace(c.Version)
	c.Type = strings.ToLower(strings.TrimSpace(c.Type))
	return c
}
