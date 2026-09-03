// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

// Package logger provides Pola's structured logging API.
package logger

import (
	"io"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Level is the severity of a log entry.
type Level int8

// Log levels, in increasing order of severity.
const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

func (l Level) zapLevel() zapcore.Level {
	switch l {
	case LevelDebug:
		return zapcore.DebugLevel
	case LevelWarn:
		return zapcore.WarnLevel
	case LevelError:
		return zapcore.ErrorLevel
	default:
		return zapcore.InfoLevel
	}
}

func levelFromZap(l zapcore.Level) Level {
	switch l {
	case zapcore.DebugLevel:
		return LevelDebug
	case zapcore.WarnLevel:
		return LevelWarn
	case zapcore.ErrorLevel:
		return LevelError
	default:
		return LevelInfo
	}
}

// Logger emits structured log entries.
type Logger struct {
	z *zap.Logger
}

// New returns a Logger that writes JSON entries to w and human-readable
// entries to console. Entries below level are discarded.
func New(w, console io.Writer, level Level) *Logger {
	ec := zap.NewProductionEncoderConfig()
	ec.EncodeTime = zapcore.ISO8601TimeEncoder

	jsonEncoder := zapcore.NewJSONEncoder(ec)
	consoleEncoder := zapcore.NewConsoleEncoder(ec)

	zl := level.zapLevel()
	core := zapcore.NewTee(
		zapcore.NewCore(jsonEncoder, zapcore.AddSync(w), zl),
		zapcore.NewCore(consoleEncoder, zapcore.AddSync(console), zl),
	)

	return &Logger{z: zap.New(core)}
}

// NewNop returns a Logger that discards every entry.
func NewNop() *Logger { return &Logger{z: zap.NewNop()} }

// Debug logs a message at debug level.
func (l *Logger) Debug(msg string, fields ...Field) { l.log(zapcore.DebugLevel, msg, fields) }

// Info logs a message at info level.
func (l *Logger) Info(msg string, fields ...Field) { l.log(zapcore.InfoLevel, msg, fields) }

// Warn logs a message at warn level.
func (l *Logger) Warn(msg string, fields ...Field) { l.log(zapcore.WarnLevel, msg, fields) }

// Error logs a message at error level.
func (l *Logger) Error(msg string, fields ...Field) { l.log(zapcore.ErrorLevel, msg, fields) }

// With returns a Logger that adds fields to every entry it emits.
func (l *Logger) With(fields ...Field) *Logger {
	return &Logger{z: l.z.With(zapFields(fields)...)}
}

// Sync flushes buffered entries.
func (l *Logger) Sync() error { return l.z.Sync() }

func (l *Logger) log(level zapcore.Level, msg string, fields []Field) {
	if ce := l.z.Check(level, msg); ce != nil {
		ce.Write(zapFields(fields)...)
	}
}
