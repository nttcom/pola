// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package logger

import "go.uber.org/zap"

// Field is a structured logging field.
type Field struct {
	zf zap.Field
}

func zapFields(fields []Field) []zap.Field {
	if len(fields) == 0 {
		return nil
	}

	out := make([]zap.Field, len(fields))
	for i, f := range fields {
		out[i] = f.zf
	}

	return out
}

// Any returns a Field containing an arbitrary value.
func Any(key string, val any) Field { return Field{zf: zap.Any(key, val)} }

// Error returns a Field containing an error.
func Error(err error) Field { return Field{zf: zap.Error(err)} }

// Int returns a Field containing an int.
func Int(key string, val int) Field { return Field{zf: zap.Int(key, val)} }

// String returns a Field containing a string.
func String(key, val string) Field { return Field{zf: zap.String(key, val)} }

// Uint8 returns a Field containing a uint8.
func Uint8(key string, val uint8) Field { return Field{zf: zap.Uint8(key, val)} }

// Uint32 returns a Field containing a uint32.
func Uint32(key string, val uint32) Field { return Field{zf: zap.Uint32(key, val)} }

// Uint32s returns a Field containing uint32 values.
func Uint32s(key string, vals []uint32) Field { return Field{zf: zap.Uint32s(key, vals)} }
