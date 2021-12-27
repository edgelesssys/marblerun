package updatelog

import (
	"net/url"
	"strings"
	"sync"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	mutex   sync.Mutex
	newSink zap.Sink
)

func init() {
	zap.RegisterSink("updatelog", func(u *url.URL) (zap.Sink, error) {
		return newSink, nil
	})
}

// Logger is an update logger.
type Logger struct {
	strings.Builder
	*zap.Logger
}

// New returns an initialized Logger.
func New() (*Logger, error) {
	config := zap.Config{
		Level:         zap.NewAtomicLevelAt(zapcore.InfoLevel),
		Development:   false,
		DisableCaller: true,
		Encoding:      "json",
		EncoderConfig: zapcore.EncoderConfig{
			MessageKey: "update",
			TimeKey:    "time",
			EncodeTime: zapcore.ISO8601TimeEncoder,
		},
		OutputPaths: []string{
			"updatelog://",
		},
	}

	logger := &Logger{}
	var err error

	mutex.Lock()
	newSink = logger
	logger.Logger, err = config.Build()
	newSink = nil
	mutex.Unlock()

	if err != nil {
		return nil, err
	}
	return logger, nil
}

// Close implements the zap.Sink interface.
func (*Logger) Close() error { return nil }

// Sync implements the zap.Sink interface.
func (*Logger) Sync() error { return nil }
