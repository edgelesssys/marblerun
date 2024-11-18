/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package logging

import (
	"log"

	"github.com/edgelesssys/marblerun/coordinator/constants"
	"github.com/edgelesssys/marblerun/util"
	"go.uber.org/zap"
)

// New creates a new [*zap.Logger].
func New() (*zap.Logger, error) {
	var cfg zap.Config
	if util.Getenv(constants.DevMode, constants.DevModeDefault) == "1" {
		cfg = zap.NewDevelopmentConfig()
	} else {
		cfg = zap.NewProductionConfig()
		cfg.DisableStacktrace = true // Disable stacktraces in production
	}
	log, err := cfg.Build()
	if err != nil {
		return nil, err
	}
	return log, nil
}

// NewWrapper creates a new [*log.Logger] that writes to the given [*zap.Logger].
func NewWrapper(zapLogger *zap.Logger) *log.Logger {
	return log.New(logWrapper{zapLogger}, "", 0)
}

// logWrapper implements [io.Writer] by writing any data to the error level of the embedded [*zap.Logger].
type logWrapper struct {
	*zap.Logger
}

func (l logWrapper) Write(p []byte) (n int, err error) {
	l.Error(string(p))
	return len(p), nil
}
