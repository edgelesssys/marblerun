package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCliCompletion(t *testing.T) {
	assert := assert.New(t)

	bashCompletion, err := cliCompletion("bash", rootCmd)
	assert.NoError(err)
	assert.Contains(bashCompletion, "# bash completion for marblerun")

	fishCompletion, err := cliCompletion("fish", rootCmd)
	assert.NoError(err)
	assert.Contains(fishCompletion, "# fish completion for marblerun")

	zshCompletion, err := cliCompletion("zsh", rootCmd)
	assert.NoError(err)
	assert.Contains(zshCompletion, "# zsh completion for marblerun")

	_, err = cliCompletion("unsupproted-shell", rootCmd)
	assert.Error(err)
}
