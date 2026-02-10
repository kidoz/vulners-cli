package report

import (
	"cmp"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"text/tabwriter"
)

// TableReporter writes output as a human-readable table.
type TableReporter struct{}

func (r *TableReporter) Write(w io.Writer, data any) error {
	raw, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshaling data for table: %w", err)
	}

	var generic any
	if err := json.Unmarshal(raw, &generic); err != nil {
		return fmt.Errorf("unmarshaling for table: %w", err)
	}

	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)

	switch v := generic.(type) {
	case []any:
		if err := writeSliceTable(tw, v); err != nil {
			return err
		}
	case map[string]any:
		writeMapTable(tw, v)
	default:
		_, _ = fmt.Fprintf(tw, "%v\n", data)
	}

	return tw.Flush()
}

func writeSliceTable(tw *tabwriter.Writer, items []any) error {
	if len(items) == 0 {
		_, _ = fmt.Fprintln(tw, "(no results)")
		return nil
	}

	first, ok := items[0].(map[string]any)
	if !ok {
		for _, item := range items {
			_, _ = fmt.Fprintf(tw, "%v\n", item)
		}
		return nil
	}

	keys := sortedKeys(first)
	for i, k := range keys {
		if i > 0 {
			_, _ = fmt.Fprint(tw, "\t")
		}
		_, _ = fmt.Fprint(tw, k)
	}
	_, _ = fmt.Fprintln(tw)

	for _, item := range items {
		row, ok := item.(map[string]any)
		if !ok {
			continue
		}
		for i, k := range keys {
			if i > 0 {
				_, _ = fmt.Fprint(tw, "\t")
			}
			_, _ = fmt.Fprintf(tw, "%v", truncate(fmt.Sprintf("%v", row[k]), 80))
		}
		_, _ = fmt.Fprintln(tw)
	}

	return nil
}

func writeMapTable(tw *tabwriter.Writer, m map[string]any) {
	for _, k := range sortedKeys(m) {
		_, _ = fmt.Fprintf(tw, "%s\t%v\n", k, truncate(fmt.Sprintf("%v", m[k]), 120))
	}
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, cmp.Compare)
	return keys
}

func truncate(s string, max int) string {
	if max <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	if max <= 3 {
		return string(r[:max])
	}
	return string(r[:max-3]) + "..."
}
