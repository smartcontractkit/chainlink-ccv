package logging

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// DevelopmentConfig returns a logging configuration with reasonable defaults for
// development.
// Time is encoded in ISO8601 format and level is encoded in capital letters.
func DevelopmentConfig(level zapcore.Level) func(*zap.Config) {
	return func(config *zap.Config) {
		config.Level = zap.NewAtomicLevelAt(level)
		// Capture stack traces at WARN level or higher.
		config.Development = true
		// Always show caller information in the logs w/ file name and line number.
		config.DisableCaller = false
		// Always show stack traces. This is useful for debugging.
		config.DisableStacktrace = false
		// Console encoding is more readable for development.
		config.Encoding = "console"
		// Encode level as capital letters for readability.
		config.EncoderConfig.EncodeLevel = zapcore.CapitalLevelEncoder
		// Encode time as ISO8601 for readability vs. scientific notation or just unix timestamps.
		config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
		// Encode duration using the default Go stringer.
		config.EncoderConfig.EncodeDuration = zapcore.StringDurationEncoder
	}
}
