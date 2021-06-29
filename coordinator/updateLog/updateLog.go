package updateLog

import (
	"net/url"
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// UpdateLog wraps a zap logger and string sink
type Logger struct {
	*StringSink
	*zap.Logger
}

// New returns an initialised UpdateLog
func New() (*Logger, error) {
	sink := &StringSink{new(strings.Builder)}

	// the only error we can get here is the sink already being registered
	// since we only care about keeping a single instance of update log we ignore this error
	zap.RegisterSink("string", func(*url.URL) (zap.Sink, error) {
		return sink, nil
	})

	zapper, err := zap.Config{
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
			"string://",
		},
	}.Build()

	return &Logger{sink, zapper}, err
}

// stringSink is a sink for writing a log to string
type StringSink struct {
	*strings.Builder
}

// Close implements the zap.Sink interface
func (s *StringSink) Close() error { return nil }

// Sync implements the zap.Sink interface
func (s *StringSink) Sync() error { return nil }
