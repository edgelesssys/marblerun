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
	"go.uber.org/zap/zapcore"
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

	if util.Getenv(constants.DebugLogging, constants.DebugLoggingDefault) == "1" {
		cfg.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	}

	log, err := cfg.Build()
	if err != nil {
		return nil, err
	}
	log.Debug("Debug logging enabled")
	return log, nil
}

// NewHTTPLogWrapper creates a new [*log.Logger] for http servers that writes to the given [*zap.Logger].
func NewHTTPLogWrapper(zapLogger *zap.Logger) *log.Logger {
	levelStr := util.Getenv(constants.HTTPErrorLogLevel, constants.HTTPErrorLogLevelDefault)
	logLevel, err := zapcore.ParseLevel(levelStr)
	if err != nil {
		zapLogger.Error("Failed to parse log level for HTTP error log from env variable, defaulting to error level", zap.String("env", constants.HTTPErrorLogLevel), zap.String("level", levelStr), zap.Error(err))
		logLevel = zapcore.ErrorLevel
	}

	var logFunc func(msg string, fields ...zap.Field)
	switch logLevel {
	case zap.DebugLevel:
		logFunc = zapLogger.Debug
	case zap.InfoLevel:
		logFunc = zapLogger.Info
	case zap.WarnLevel:
		logFunc = zapLogger.Warn
	case zap.ErrorLevel:
		logFunc = zapLogger.Error
	default:
		logFunc = zapLogger.Error
	}
	return log.New(logWrapper{logFunc}, "", 0)
}

// logWrapper implements [io.Writer] by writing any data to the error level of the embedded [*zap.Logger].
type logWrapper struct {
	logFunc func(msg string, fields ...zap.Field)
}

func (l logWrapper) Write(p []byte) (n int, err error) {
	l.logFunc(string(p))
	return len(p), nil
}
