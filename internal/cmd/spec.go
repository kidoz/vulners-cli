package cmd

import (
	"github.com/alecthomas/kong"
)

// SpecCmd outputs machine-readable command/flag definitions.
type SpecCmd struct{}

// SpecOutput is the top-level JSON output of the spec command.
type SpecOutput struct {
	Commands []SpecCommand `json:"commands"`
	Globals  []SpecFlag    `json:"globals"`
}

// SpecCommand describes a CLI command.
type SpecCommand struct {
	Name     string        `json:"name"`
	Help     string        `json:"help,omitempty"`
	Aliases  []string      `json:"aliases,omitempty"`
	Hidden   bool          `json:"hidden,omitempty"`
	Flags    []SpecFlag    `json:"flags,omitempty"`
	Args     []SpecArg     `json:"args,omitempty"`
	Commands []SpecCommand `json:"commands,omitempty"`
}

// SpecFlag describes a CLI flag.
type SpecFlag struct {
	Name     string `json:"name"`
	Help     string `json:"help,omitempty"`
	Type     string `json:"type,omitempty"`
	Default  string `json:"default,omitempty"`
	Enum     string `json:"enum,omitempty"`
	Required bool   `json:"required,omitempty"`
	Short    string `json:"short,omitempty"`
	Hidden   bool   `json:"hidden,omitempty"`
}

// SpecArg describes a positional argument.
type SpecArg struct {
	Name     string `json:"name"`
	Help     string `json:"help,omitempty"`
	Required bool   `json:"required,omitempty"`
}

func (c *SpecCmd) Run(globals *CLI, k *kong.Kong) error {
	if err := validateNonScanFormat(globals.Output); err != nil {
		return err
	}

	app := k.Model

	output := SpecOutput{
		Globals:  extractFlags(app.Flags),
		Commands: extractCommands(app.Children),
	}

	w, closer, werr := outputWriter(globals)
	if werr != nil {
		return werr
	}
	defer func() { _ = closer() }()

	return writeIntelOutput(w, globals, "spec", output, nil)
}

func extractCommands(nodes []*kong.Node) []SpecCommand {
	var cmds []SpecCommand
	for _, n := range nodes {
		if n.Type != kong.CommandNode {
			continue
		}
		cmd := SpecCommand{
			Name:    n.Name,
			Help:    n.Help,
			Aliases: n.Aliases,
			Hidden:  n.Hidden,
			Flags:   extractFlags(n.Flags),
			Args:    extractArgs(n.Positional),
		}
		if len(n.Children) > 0 {
			cmd.Commands = extractCommands(n.Children)
		}
		cmds = append(cmds, cmd)
	}
	return cmds
}

func extractFlags(flags []*kong.Flag) []SpecFlag {
	var out []SpecFlag
	for _, f := range flags {
		if f.Name == "help" {
			continue // Skip the built-in help flag.
		}
		sf := SpecFlag{
			Name:     f.Name,
			Help:     f.Help,
			Default:  f.Default,
			Enum:     f.Enum,
			Required: f.Required,
			Hidden:   f.Hidden,
		}
		if f.Target.IsValid() {
			sf.Type = f.Target.Type().String()
		}
		if f.Short != 0 {
			sf.Short = string(f.Short)
		}
		out = append(out, sf)
	}
	return out
}

func extractArgs(args []*kong.Positional) []SpecArg {
	var out []SpecArg
	for _, a := range args {
		out = append(out, SpecArg{
			Name:     a.Name,
			Help:     a.Help,
			Required: a.Required,
		})
	}
	return out
}
