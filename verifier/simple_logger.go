package verifier

import (
	"github.com/rs/zerolog"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

// SimpleLogger implements the chainlink logger interface using zerolog
type SimpleLogger struct {
	zl zerolog.Logger
}

// NewSimpleLogger creates a new simple logger
func NewSimpleLogger(zl zerolog.Logger) logger.Logger {
	return &SimpleLogger{zl: zl}
}

// Debug logs at debug level
func (s *SimpleLogger) Debug(args ...interface{}) {
	s.zl.Debug().Msgf("%v", args)
}

// Info logs at info level
func (s *SimpleLogger) Info(args ...interface{}) {
	s.zl.Info().Msgf("%v", args)
}

// Warn logs at warn level
func (s *SimpleLogger) Warn(args ...interface{}) {
	s.zl.Warn().Msgf("%v", args)
}

// Error logs at error level
func (s *SimpleLogger) Error(args ...interface{}) {
	s.zl.Error().Msgf("%v", args)
}

// Panic logs at panic level and panics
func (s *SimpleLogger) Panic(args ...interface{}) {
	s.zl.Panic().Msgf("%v", args)
}

// Fatal logs at fatal level and exits
func (s *SimpleLogger) Fatal(args ...interface{}) {
	s.zl.Fatal().Msgf("%v", args)
}

// Debugf logs formatted debug message
func (s *SimpleLogger) Debugf(format string, args ...interface{}) {
	s.zl.Debug().Msgf(format, args...)
}

// Infof logs formatted info message
func (s *SimpleLogger) Infof(format string, args ...interface{}) {
	s.zl.Info().Msgf(format, args...)
}

// Warnf logs formatted warn message
func (s *SimpleLogger) Warnf(format string, args ...interface{}) {
	s.zl.Warn().Msgf(format, args...)
}

// Errorf logs formatted error message
func (s *SimpleLogger) Errorf(format string, args ...interface{}) {
	s.zl.Error().Msgf(format, args...)
}

// Panicf logs formatted panic message and panics
func (s *SimpleLogger) Panicf(format string, args ...interface{}) {
	s.zl.Panic().Msgf(format, args...)
}

// Fatalf logs formatted fatal message and exits
func (s *SimpleLogger) Fatalf(format string, args ...interface{}) {
	s.zl.Fatal().Msgf(format, args...)
}

// Debugw logs debug message with key-value pairs
func (s *SimpleLogger) Debugw(msg string, keysAndValues ...interface{}) {
	event := s.zl.Debug()
	s.addFields(event, keysAndValues...)
	event.Msg(msg)
}

// Infow logs info message with key-value pairs
func (s *SimpleLogger) Infow(msg string, keysAndValues ...interface{}) {
	event := s.zl.Info()
	s.addFields(event, keysAndValues...)
	event.Msg(msg)
}

// Warnw logs warn message with key-value pairs
func (s *SimpleLogger) Warnw(msg string, keysAndValues ...interface{}) {
	event := s.zl.Warn()
	s.addFields(event, keysAndValues...)
	event.Msg(msg)
}

// Errorw logs error message with key-value pairs
func (s *SimpleLogger) Errorw(msg string, keysAndValues ...interface{}) {
	event := s.zl.Error()
	s.addFields(event, keysAndValues...)
	event.Msg(msg)
}

// Panicw logs panic message with key-value pairs and panics
func (s *SimpleLogger) Panicw(msg string, keysAndValues ...interface{}) {
	event := s.zl.Panic()
	s.addFields(event, keysAndValues...)
	event.Msg(msg)
}

// Fatalw logs fatal message with key-value pairs and exits
func (s *SimpleLogger) Fatalw(msg string, keysAndValues ...interface{}) {
	event := s.zl.Fatal()
	s.addFields(event, keysAndValues...)
	event.Msg(msg)
}

// With creates a new logger with additional fields
func (s *SimpleLogger) With(keysAndValues ...interface{}) logger.Logger {
	newLogger := s.zl.With()
	for i := 0; i < len(keysAndValues); i += 2 {
		if i+1 < len(keysAndValues) {
			key := keysAndValues[i]
			value := keysAndValues[i+1]
			newLogger = newLogger.Interface(key.(string), value)
		}
	}
	return &SimpleLogger{zl: newLogger.Logger()}
}

// Named creates a new logger with a name
func (s *SimpleLogger) Named(name string) logger.Logger {
	return &SimpleLogger{zl: s.zl.With().Str("name", name).Logger()}
}

// Name returns the logger name (not implemented for simple logger)
func (s *SimpleLogger) Name() string {
	return "simple-logger"
}

// Sync flushes any buffered log entries (no-op for zerolog)
func (s *SimpleLogger) Sync() error {
	return nil
}

// addFields adds key-value pairs to zerolog event
func (s *SimpleLogger) addFields(event *zerolog.Event, keysAndValues ...interface{}) {
	for i := 0; i < len(keysAndValues); i += 2 {
		if i+1 < len(keysAndValues) {
			key := keysAndValues[i]
			value := keysAndValues[i+1]
			event.Interface(key.(string), value)
		}
	}
}
