// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cmd

import (
	"bytes"
	"fmt"

	"github.com/spf13/cobra"
)

func newCompletionCmd() *cobra.Command {
	example := `
  	For bash:
  	source <(marblerun completion bash)

	For zsh:
	If shell completion is not already enabled in your environment you will need to enable it:
	echo "autoload -U compinit; compinit" >> ~/.zshrc

	To load completions for each session, execute once:
	marblerun completion zsh > "${fpath[1]}/_marblerun"
	`
	cmd := &cobra.Command{
		Use:                   "completion",
		Short:                 "Output script for specified shell to enable autocompletion",
		Long:                  `Output script for specified shell to enable autocompletion`,
		Example:               example,
		Args:                  cobra.ExactArgs(1),
		ValidArgs:             []string{"bash", "zsh"},
		DisableFlagsInUseLine: true,
		SilenceErrors:         true,
		RunE: func(cmd *cobra.Command, args []string) error {
			shell := args[0]
			out, err := cliCompletion(shell, cmd.Root())
			if err != nil {
				return err
			}
			fmt.Print(out)
			return nil
		},
	}

	return cmd
}

// cliCompletion returns the autocompletion script for the specified shell.
func cliCompletion(shell string, parent *cobra.Command) (string, error) {
	var buf bytes.Buffer
	var err error

	switch shell {
	case "bash":
		err = parent.GenBashCompletion(&buf)
	// case "fish":
	//	err = parent.GenFishCompletion(&buf, false)
	case "zsh":
		err = parent.GenZshCompletion(&buf)
	default:
		err = fmt.Errorf("unsupported shell type [%s]", shell)
	}

	return buf.String(), err
}
