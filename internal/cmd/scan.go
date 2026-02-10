package cmd

// ScanCmd is the command group for scanning targets.
type ScanCmd struct {
	Repo  ScanRepoCmd  `cmd:"" help:"Scan a repository for vulnerabilities"`
	SBOM  ScanSBOMCmd  `cmd:"" name:"sbom" help:"Scan an SBOM file"`
	Image ScanImageCmd `cmd:"" help:"Scan a container image (requires syft)"`
	Dir   ScanDirCmd   `cmd:"" help:"Scan a directory for package manifests"`
}
