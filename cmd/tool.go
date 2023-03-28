package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"pon-relay.com/cmd/tool"
)

func init() {
	toolCmd.AddCommand(tool.DataAPIExportPayloads)
	toolCmd.AddCommand(tool.DataAPIExportBids)
	toolCmd.AddCommand(tool.ArchiveExecutionPayloads)
	toolCmd.AddCommand(tool.Migrate)
	rootCmd.AddCommand(toolCmd)
}

var toolCmd = &cobra.Command{
	Use:   "tool",
	Short: "tools for managing the database",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Error: please use a valid subcommand")
		_ = cmd.Help()
	},
}
