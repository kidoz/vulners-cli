# Documentation

This documentation follows the [Diátaxis](https://diataxis.fr/) framework: pages are grouped by what the reader is trying to do, not by product area.

| Quadrant | Use it when you want to... | Start here |
|---|---|---|
| Tutorials | learn by doing, from a working example | [Get started](tutorials/getting-started.md) |
| How-to guides | complete a specific task | [GitHub Actions](how-to/github-actions.md) · [GitLab CI](how-to/gitlab-ci.md) |
| Reference | look up exact commands, flags, formats, or exit codes | [CLI reference](reference/cli.md) |
| Explanation | understand how scanning works and why | [Scanning model](explanation/scanning-model.md) |

## Choosing a quadrant

- If you are new to `vulners-cli`, start with the tutorial.
- If you already know what you want to do, use a how-to guide.
- If you need exact values, use the reference.
- If you need background or design rationale, use the explanation.

For the project overview, installation options, and contribution information, see the [README](../README.md).

## Adding documentation

Decide which quadrant a page belongs to before writing it:

- **Tutorials** — one guided lesson with a guaranteed outcome. Teach the minimum needed to finish.
- **How-to guides** — steps for one real task. Assume the reader already knows the basics.
- **Reference** — terse, complete facts such as commands, flags, schemas, and exit codes.
- **Explanation** — concepts, architecture, trade-offs, and limitations.

Link to the other quadrants instead of mixing their content into one page.
