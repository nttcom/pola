// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package logger

import (
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func LogInit(fp *os.File) *zap.Logger {
	pe := zap.NewProductionEncoderConfig()
	fileEncoder := zapcore.NewJSONEncoder(pe)
	pe.EncodeTime = zapcore.ISO8601TimeEncoder
	consoleEncoder := zapcore.NewConsoleEncoder(pe)
	level := zap.InfoLevel
	core := zapcore.NewTee(
		zapcore.NewCore(fileEncoder, zapcore.AddSync(fp), level),
		zapcore.NewCore(consoleEncoder, zapcore.AddSync(os.Stdout), level),
	)
	return zap.New(core)
}
