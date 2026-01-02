package logging

import (
	"os"
	"strings"
	"sync"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	globalLogger *zap.Logger
	once         sync.Once
)

// Level represents log levels
type Level string

const (
	LevelDebug Level = "debug"
	LevelInfo  Level = "info"
	LevelWarn  Level = "warn"
	LevelError Level = "error"
	LevelFatal Level = "fatal"
)

// Config holds logger configuration
type Config struct {
	Level      Level  `yaml:"level" json:"level"`
	Format     string `yaml:"format" json:"format"` // "json" or "console"
	OutputPath string `yaml:"output_path" json:"output_path"`
}

// DefaultConfig returns default logging configuration
func DefaultConfig() *Config {
	return &Config{
		Level:      LevelInfo,
		Format:     "json",
		OutputPath: "stdout",
	}
}

// Init initializes the global logger
func Init(cfg *Config) error {
	var err error
	once.Do(func() {
		globalLogger, err = NewLogger(cfg)
	})
	return err
}

// NewLogger creates a new logger with the given configuration
func NewLogger(cfg *Config) (*zap.Logger, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	level := parseLevel(cfg.Level)

	var encoder zapcore.Encoder
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.TimeKey = "timestamp"
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	encoderConfig.EncodeLevel = zapcore.CapitalLevelEncoder

	if cfg.Format == "console" {
		encoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
		encoder = zapcore.NewConsoleEncoder(encoderConfig)
	} else {
		encoder = zapcore.NewJSONEncoder(encoderConfig)
	}

	var output zapcore.WriteSyncer
	switch cfg.OutputPath {
	case "stdout", "":
		output = zapcore.AddSync(os.Stdout)
	case "stderr":
		output = zapcore.AddSync(os.Stderr)
	default:
		file, err := os.OpenFile(cfg.OutputPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return nil, err
		}
		output = zapcore.AddSync(file)
	}

	core := zapcore.NewCore(encoder, output, level)
	logger := zap.New(core, zap.AddCaller(), zap.AddStacktrace(zapcore.ErrorLevel))

	return logger, nil
}

func parseLevel(level Level) zapcore.Level {
	switch strings.ToLower(string(level)) {
	case "debug":
		return zapcore.DebugLevel
	case "info":
		return zapcore.InfoLevel
	case "warn", "warning":
		return zapcore.WarnLevel
	case "error":
		return zapcore.ErrorLevel
	case "fatal":
		return zapcore.FatalLevel
	default:
		return zapcore.InfoLevel
	}
}

// Get returns the global logger
func Get() *zap.Logger {
	if globalLogger == nil {
		// Return a no-op logger if not initialized
		return zap.NewNop()
	}
	return globalLogger
}

// Sugar returns a sugared logger
func Sugar() *zap.SugaredLogger {
	return Get().Sugar()
}

// With creates a child logger with additional fields
func With(fields ...zap.Field) *zap.Logger {
	return Get().With(fields...)
}

// Debug logs a debug message
func Debug(msg string, fields ...zap.Field) {
	Get().Debug(msg, fields...)
}

// Info logs an info message
func Info(msg string, fields ...zap.Field) {
	Get().Info(msg, fields...)
}

// Warn logs a warning message
func Warn(msg string, fields ...zap.Field) {
	Get().Warn(msg, fields...)
}

// Error logs an error message
func Error(msg string, fields ...zap.Field) {
	Get().Error(msg, fields...)
}

// Fatal logs a fatal message and exits
func Fatal(msg string, fields ...zap.Field) {
	Get().Fatal(msg, fields...)
}

// Sync flushes any buffered log entries
func Sync() error {
	if globalLogger != nil {
		return globalLogger.Sync()
	}
	return nil
}
