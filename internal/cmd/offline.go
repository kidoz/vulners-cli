package cmd

// OfflineCmd is the command group for offline mode management.
type OfflineCmd struct {
	Sync   OfflineSyncCmd   `cmd:"" help:"Sync vulnerability data for offline use"`
	Status OfflineStatusCmd `cmd:"" help:"Show offline database status"`
	Purge  OfflinePurgeCmd  `cmd:"" help:"Purge offline database"`
}
