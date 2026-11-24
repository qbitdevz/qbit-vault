package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/qbitdevz/qbit-vault/internal/audit"
	"github.com/qbitdevz/qbit-vault/internal/prompt"
)

type revertBody struct {
	OK       bool   `json:"ok"`
	Name     string `json:"name"`
	Layer    string `json:"layer"`
	Reverted bool   `json:"reverted"`
	// GrantsDropped counts the grants the revert dropped; omitted when none.
	GrantsDropped int `json:"grants_dropped,omitempty"`
	// PreviousUntil is the end of the window in which the revert can be
	// undone (the value it set aside); a time, never a value.
	PreviousUntil string `json:"previous_until,omitempty"`
	// Remote is "synced" or "pending" when the vault syncs.
	Remote string `json:"remote,omitempty"`
}

// newRevert is `qbit-vault revert NAME`: swap the current value with the one
// it replaced (STORAGE.md § Previous value). The user is asked on the
// controlling terminal or by a dialog unless --yes; no value is ever printed.
func newRevert(g *globals) *cobra.Command {
	var (
		lf  layerFlags
		yes bool
	)
	cmd := &cobra.Command{
		Use:   "revert NAME [--global|--project] [--yes]",
		Short: "Restore the value a secret had before its last replacement (kept 7 days)",
		Long: "Swap the value of NAME with the one it replaced, when that replacement was less than 7 days ago.\n" +
			"The current value becomes the previous one, so a revert can be undone with another revert; the secret\n" +
			"gets a new id and its grants are dropped, as in any replacement. No value is printed.",
		Args: nameArg,
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			if err := lf.validate(); err != nil {
				return err
			}
			var ask prompt.Backend
			if !yes {
				var err error
				if ask, err = g.backend(); err != nil {
					return orInstead(err, usageError{"confirmation required; pass --yes"})
				}
			}
			if err := checkName(name); err != nil {
				return err
			}
			cwd, err := getwd()
			if err != nil {
				return err
			}
			s, err := g.openSession()
			if err != nil {
				return err
			}
			defer s.close()
			e, err := findEntry(s, name, lf, cwd)
			if err != nil {
				return err
			}
			e.Record.Value.Wipe()
			until, ok := e.Record.PreviousUntil()
			if !ok {
				return noPreviousValue(name)
			}
			if !yes {
				loc := g.loc()
				if err := confirmChange(ask, loc.T("q.revert", name, whereText(loc, e.Layer), replacedOnText(until)), usageError{"confirmation required; pass --yes"}); err != nil {
					return err
				}
			}
			res, err := s.v.RevertWithGrants(e.Layer, name, newGrantsEditor())
			if err != nil {
				return mapErr(err, name)
			}
			g.noteGrantsReset(cmd.ErrOrStderr(), res.Reset)
			g.record(cmd.ErrOrStderr(), audit.Record{Event: audit.EventEdit, Names: []string{name}, Layer: auditLayer(e.Layer), Detail: "revert"})
			remoteState := g.pushAfterCmd(cmd, s)
			// The value set aside can be restored until the new window ends.
			undo := ""
			if after, ferr := findEntry(s, name, layerFlags{global: !e.Layer.Project, project: e.Layer.Project}, cwd); ferr == nil {
				undo = previousUntilText(after.Record)
				after.Record.Value.Wipe()
			}
			if g.JSON {
				return writeJSON(cmd.OutOrStdout(), revertBody{OK: true, Name: name, Layer: layerName(e.Layer), Reverted: true,
					GrantsDropped: res.Changed, PreviousUntil: undo, Remote: remoteState})
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "restored the previous value of %s (%s); revert again until %s to undo\n", name, layerText(e.Layer), undo)
			return err
		},
	}
	lf.bind(cmd)
	cmd.Flags().BoolVar(&yes, "yes", false, "revert without asking (for scripts)")
	return cmd
}
