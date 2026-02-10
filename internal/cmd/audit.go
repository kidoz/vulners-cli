package cmd

// AuditCmd is the command group for OS package auditing.
type AuditCmd struct {
	Linux    LinuxAuditCmd   `cmd:"" help:"Audit Linux packages"`
	Windows  WindowsAuditCmd `cmd:"" help:"Audit Windows KB updates"`
	Host     HostAuditCmd    `cmd:"" help:"Audit host packages (v4 API)"`
	Winaudit WinFullAuditCmd `cmd:"" name:"winaudit" help:"Full Windows audit (KBs + software)"`
}
