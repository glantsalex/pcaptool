package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/aglants/pcaptool/internal/direction"
	"github.com/spf13/cobra"
)

func newDirectionRegistryCommand(opts *DNSExtractOptions, merge bool) *cobra.Command {
	var registry, discoveries, day, output, account string
	name := "render-flow-direction-sql"
	if merge {
		name = "merge-direction-registry"
	}
	c := &cobra.Command{Use: name, Short: "Offline versioned direction registry tooling", Args: cobra.NoArgs, RunE: func(c *cobra.Command, _ []string) error {
		if !direction.Identifier.MatchString(opts.NetID) || !direction.Identifier.MatchString(account) {
			return fmt.Errorf("valid --net-id and --account required")
		}
		old := direction.Document{SchemaVersion: direction.Version, AccountID: account, StreamID: opts.NetID, Endpoints: []direction.Endpoint{}}
		if registry != "" {
			data, err := os.ReadFile(registry)
			if err != nil {
				return err
			}
			old, err = direction.Decode(data)
			if err != nil {
				return err
			}
		} else if !merge {
			return fmt.Errorf("--registry required")
		}
		if err := old.ValidateRegistry(account, opts.NetID); err != nil {
			return err
		}
		var data []byte
		if merge {
			raw, err := os.ReadFile(discoveries)
			if err != nil {
				return err
			}
			daily, err := direction.Decode(raw)
			if err != nil {
				return err
			}
			d, err := direction.Merge(old, daily, account, opts.NetID, day)
			if err != nil {
				return err
			}
			data, err = json.MarshalIndent(d, "", "  ")
			if err != nil {
				return err
			}
			data = append(data, '\n')
		} else {
			data = []byte(flowDirectionCorrectionSQLForDocument(opts.NetID, old))
		}
		if output == "" {
			return fmt.Errorf("--output required")
		}
		return os.WriteFile(output, data, 0600)
	}}
	c.Flags().StringVar(&registry, "registry", "", "Existing cumulative registry (omit only for initial merge)")
	c.Flags().StringVar(&account, "account", "", "Account identifier")
	c.Flags().StringVar(&output, "output", "", "Output file")
	if merge {
		c.Flags().StringVar(&discoveries, "discoveries", "", "Daily private-nonfleet-endpoints.json")
		c.Flags().StringVar(&day, "date", "", "PCAP data day YYYY-MM-DD")
	}
	return c
}
