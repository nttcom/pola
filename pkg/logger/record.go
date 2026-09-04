// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package logger

import (
	"reflect"
	"sync"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Entry is a recorded log entry.
type Entry struct {
	Level   Level
	Message string
	Fields  map[string]any
}

// Recorder holds recorded log entries. It is safe for concurrent use.
type Recorder struct {
	mu      sync.Mutex
	entries []Entry
}

// NewRecorder returns a Logger and Recorder for recording log entries.
// Entries below level are discarded.
func NewRecorder(level Level) (*Logger, *Recorder) {
	rec := &Recorder{}
	core := &recordCore{min: level.zapLevel(), rec: rec}

	return &Logger{z: zap.New(core)}, rec
}

// All returns every recorded entry, oldest first.
func (r *Recorder) All() []Entry {
	r.mu.Lock()
	defer r.mu.Unlock()

	out := make([]Entry, len(r.entries))
	for i, e := range r.entries {
		out[i] = cloneEntry(e)
	}

	return out
}

// Len returns the number of recorded entries.
func (r *Recorder) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()

	return len(r.entries)
}

// FilterByMessage returns the recorded entries whose message equals msg.
func (r *Recorder) FilterByMessage(msg string) []Entry {
	r.mu.Lock()
	defer r.mu.Unlock()

	var out []Entry

	for _, e := range r.entries {
		if e.Message == msg {
			out = append(out, cloneEntry(e))
		}
	}

	return out
}

func cloneEntry(e Entry) Entry {
	e.Fields = cloneFields(e.Fields)
	return e
}

func cloneFields(fields map[string]any) map[string]any {
	if fields == nil {
		return nil
	}

	out := make(map[string]any, len(fields))
	for k, v := range fields {
		out[k] = cloneValue(v)
	}

	return out
}

func cloneValue(v any) any {
	switch t := v.(type) {
	case map[string]any:
		return cloneFields(t)
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = cloneValue(e)
		}

		return out
	}

	switch rv := reflect.ValueOf(v); rv.Kind() {
	case reflect.Map, reflect.Slice, reflect.Array, reflect.Pointer:
		return cloneReflectValue(rv).Interface()
	default:
		return v
	}
}

func cloneReflectValue(rv reflect.Value) reflect.Value {
	switch rv.Kind() {
	case reflect.Pointer:
		return clonePointer(rv)
	case reflect.Map:
		return cloneMap(rv)
	case reflect.Slice:
		return cloneSlice(rv)
	case reflect.Array:
		return cloneArray(rv)
	case reflect.Interface:
		return cloneInterface(rv)
	case reflect.Struct:
		return cloneStruct(rv)
	default:
		return rv
	}
}

func clonePointer(rv reflect.Value) reflect.Value {
	if rv.IsNil() {
		return rv
	}

	out := reflect.New(rv.Type().Elem())
	out.Elem().Set(cloneReflectValue(rv.Elem()))

	return out
}

func cloneMap(rv reflect.Value) reflect.Value {
	if rv.IsNil() {
		return rv
	}

	out := reflect.MakeMapWithSize(rv.Type(), rv.Len())
	for iter := rv.MapRange(); iter.Next(); {
		out.SetMapIndex(iter.Key(), cloneReflectValue(iter.Value()))
	}

	return out
}

func cloneSlice(rv reflect.Value) reflect.Value {
	if rv.IsNil() {
		return rv
	}

	out := reflect.MakeSlice(rv.Type(), rv.Len(), rv.Len())
	for i := range rv.Len() {
		out.Index(i).Set(cloneReflectValue(rv.Index(i)))
	}

	return out
}

func cloneArray(rv reflect.Value) reflect.Value {
	out := reflect.New(rv.Type()).Elem()
	for i := range rv.Len() {
		out.Index(i).Set(cloneReflectValue(rv.Index(i)))
	}

	return out
}

func cloneInterface(rv reflect.Value) reflect.Value {
	if rv.IsNil() {
		return rv
	}

	out := reflect.New(rv.Type()).Elem()
	out.Set(reflect.ValueOf(cloneValue(rv.Interface())))

	return out
}

// Copy first because unexported fields cannot be set individually.
func cloneStruct(rv reflect.Value) reflect.Value {
	out := reflect.New(rv.Type()).Elem()
	out.Set(rv)

	for i := range rv.NumField() {
		if rv.Type().Field(i).IsExported() {
			out.Field(i).Set(cloneReflectValue(rv.Field(i)))
		}
	}

	return out
}

func (r *Recorder) add(e Entry) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.entries = append(r.entries, e)
}

type recordCore struct {
	min zapcore.Level
	rec *Recorder
	ctx []zapcore.Field
}

func (c *recordCore) Enabled(l zapcore.Level) bool { return l >= c.min }

func (c *recordCore) With(fields []zapcore.Field) zapcore.Core {
	ctx := make([]zapcore.Field, 0, len(c.ctx)+len(fields))
	ctx = append(ctx, c.ctx...)
	ctx = append(ctx, fields...)

	return &recordCore{min: c.min, rec: c.rec, ctx: ctx}
}

func (c *recordCore) Check(e zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if c.Enabled(e.Level) {
		return ce.AddCore(e, c)
	}

	return ce
}

func (c *recordCore) Write(e zapcore.Entry, fields []zapcore.Field) error {
	enc := zapcore.NewMapObjectEncoder()
	for _, f := range c.ctx {
		f.AddTo(enc)
	}

	for _, f := range fields {
		f.AddTo(enc)
	}

	c.rec.add(cloneEntry(Entry{
		Level:   levelFromZap(e.Level),
		Message: e.Message,
		Fields:  enc.Fields,
	}))

	return nil
}

func (c *recordCore) Sync() error { return nil }
