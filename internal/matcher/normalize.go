package matcher

import (
	"strings"

	"github.com/kidoz/vulners-cli/internal/model"
)

// NormalizeComponent prepares a component for vulnerability matching.
func NormalizeComponent(c model.Component) model.Component {
	c.Name = strings.ToLower(c.Name)
	c.Type = strings.ToLower(c.Type)
	return c
}
