/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package server

import (
	"fmt"

	"github.com/edgelesssys/marblerun/coordinator/constants"
	"github.com/edgelesssys/marblerun/util"
	"go.uber.org/zap"
	"google.golang.org/grpc/grpclog"
)

func replaceGRPCLogger(l *zap.Logger) {
	options := []zap.Option{
		zap.AddCallerSkip(2),
	}
	if util.Getenv(constants.DebugLogging, constants.DebugLoggingDefault) != "1" {
		options = append(options, zap.IncreaseLevel(zap.WarnLevel))
	}

	gl := &grpcLogger{
		logger:    l.With(zap.String("system", "grpc"), zap.Bool("grpc_log", true)).WithOptions(options...),
		verbosity: 0,
	}
	grpclog.SetLoggerV2(gl)
}

type grpcLogger struct {
	logger    *zap.Logger
	verbosity int
}

func (l *grpcLogger) Info(args ...interface{}) {
	l.logger.Info(fmt.Sprint(args...))
}

func (l *grpcLogger) Infoln(args ...interface{}) {
	l.logger.Info(fmt.Sprint(args...))
}

func (l *grpcLogger) Infof(format string, args ...interface{}) {
	l.logger.Info(fmt.Sprintf(format, args...))
}

func (l *grpcLogger) Warning(args ...interface{}) {
	l.logger.Warn(fmt.Sprint(args...))
}

func (l *grpcLogger) Warningln(args ...interface{}) {
	l.logger.Warn(fmt.Sprint(args...))
}

func (l *grpcLogger) Warningf(format string, args ...interface{}) {
	l.logger.Warn(fmt.Sprintf(format, args...))
}

func (l *grpcLogger) Error(args ...interface{}) {
	l.logger.Error(fmt.Sprint(args...))
}

func (l *grpcLogger) Errorln(args ...interface{}) {
	l.logger.Error(fmt.Sprint(args...))
}

func (l *grpcLogger) Errorf(format string, args ...interface{}) {
	l.logger.Error(fmt.Sprintf(format, args...))
}

func (l *grpcLogger) Fatal(args ...interface{}) {
	l.logger.Fatal(fmt.Sprint(args...))
}

func (l *grpcLogger) Fatalln(args ...interface{}) {
	l.logger.Fatal(fmt.Sprint(args...))
}

func (l *grpcLogger) Fatalf(format string, args ...interface{}) {
	l.logger.Fatal(fmt.Sprintf(format, args...))
}

func (l *grpcLogger) V(level int) bool {
	// Check whether the verbosity of the current log ('level') is within the specified threshold ('l.verbosity').
	// As in https://github.com/grpc/grpc-go/blob/41e044e1c82fcf6a5801d6cbd7ecf952505eecb1/grpclog/loggerv2.go#L199-L201.
	return level <= l.verbosity
}
