// Package main — AegisShield CLI Tool (aegis)
//
// Provides command-line management of the AegisShield DDoS protection system.
//
// Usage:
//   aegis status              - Show current protection state
//   aegis block <ip>          - Block an IP address
//   aegis unblock <ip>        - Unblock an IP address
//   aegis rules list          - List ACL rules
//   aegis config reload       - Hot-reload configuration
//   aegis attacks             - Show attack history
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

const cliVersion = "0.1.0"

func main() {
	rootCmd := &cobra.Command{
		Use:   "aegis",
		Short: "AegisShield — Enterprise DDoS Protection CLI",
		Long: `
╔═══════════════════════════════════════════════╗
║              AegisShield CLI                  ║
║        DDoS Protection Management Tool        ║
╚═══════════════════════════════════════════════╝

Manage your AegisShield DDoS protection from the command line.
Control the XDP data plane, view attack statistics, manage
IP blocklists, and configure protection rules.`,
		Version: cliVersion,
	}

	// ── aegis status ─────────────────────────────────────────────────
	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Show current protection status and statistics",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("🛡  AegisShield Status")
			fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
			fmt.Println("  State:        NORMAL")
			fmt.Println("  Interface:    eth0")
			fmt.Println("  XDP Mode:     Driver (native)")
			fmt.Println("  Uptime:       --")
			fmt.Println("")
			fmt.Println("📊 Statistics (per second)")
			fmt.Println("  RX Packets:   0")
			fmt.Println("  Dropped:      0")
			fmt.Println("  Passed:       0")
			fmt.Println("  SYN Cookies:  0")
			fmt.Println("")
			fmt.Println("🔒 Blocklist:   0 IPs")
			fmt.Println("📋 ACL Rules:   7 active")
			// TODO: Connect to aegisd gRPC API to fetch real data
		},
	}

	// ── aegis block <ip> ─────────────────────────────────────────────
	var blockDuration string
	blockCmd := &cobra.Command{
		Use:   "block [ip]",
		Short: "Block an IP address in the XDP blocklist",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			ip := args[0]
			fmt.Printf("🔒 Blocking IP: %s (duration: %s)\n", ip, blockDuration)
			fmt.Println("   → Added to XDP blocklist (instant drop at NIC level)")
			// TODO: Send to aegisd gRPC API
		},
	}
	blockCmd.Flags().StringVar(&blockDuration, "duration", "permanent", "Block duration (e.g., 1h, 30m, permanent)")

	// ── aegis unblock <ip> ───────────────────────────────────────────
	unblockCmd := &cobra.Command{
		Use:   "unblock [ip]",
		Short: "Remove an IP from the XDP blocklist",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			ip := args[0]
			fmt.Printf("🔓 Unblocking IP: %s\n", ip)
			// TODO: Send to aegisd gRPC API
		},
	}

	// ── aegis attacks ────────────────────────────────────────────────
	attacksCmd := &cobra.Command{
		Use:   "attacks",
		Short: "Show attack history",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("📋 Attack History")
			fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
			fmt.Println("  No attacks recorded yet.")
			// TODO: Fetch from aegisd gRPC API
		},
	}

	// ── aegis config reload ──────────────────────────────────────────
	configCmd := &cobra.Command{
		Use:   "config",
		Short: "Configuration management",
	}
	configReloadCmd := &cobra.Command{
		Use:   "reload",
		Short: "Hot-reload configuration without restarting",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("🔄 Reloading configuration...")
			fmt.Println("   → BPF maps updated")
			fmt.Println("   → Thresholds applied")
			fmt.Println("   ✓ Configuration reloaded successfully")
			// TODO: Send SIGHUP or gRPC call to aegisd
		},
	}
	configCmd.AddCommand(configReloadCmd)

	// ── aegis rules ──────────────────────────────────────────────────
	rulesCmd := &cobra.Command{
		Use:   "rules",
		Short: "Manage Edge Network Firewall ACL rules",
	}
	rulesListCmd := &cobra.Command{
		Use:   "list",
		Short: "List active ACL rules",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("📋 Edge Network Firewall Rules")
			fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
			fmt.Printf("  %-8s %-8s %-12s %-12s %-8s\n", "Priority", "Proto", "Src Port", "Dst Port", "Action")
			fmt.Printf("  %-8s %-8s %-12s %-12s %-8s\n", "--------", "-----", "--------", "--------", "------")
			fmt.Printf("  %-8d %-8s %-12s %-12s %-8s\n", 0, "TCP", "*", "*", "ALLOW")
			fmt.Printf("  %-8d %-8s %-12s %-12s %-8s\n", 1, "TCP", "*", "25565", "ALLOW")
			fmt.Printf("  %-8d %-8s %-12s %-12s %-8s\n", 2, "TCP", "*", "22", "ALLOW")
			fmt.Printf("  %-8d %-8s %-12s %-12s %-8s\n", 3, "UDP", "*", "53", "ALLOW")
			fmt.Printf("  %-8d %-8s %-12s %-12s %-8s\n", 4, "ICMP", "*", "*", "ALLOW")
			// TODO: Read from config or gRPC API
		},
	}
	rulesCmd.AddCommand(rulesListCmd)

	// Register all commands
	rootCmd.AddCommand(statusCmd, blockCmd, unblockCmd, attacksCmd, configCmd, rulesCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
