// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package logger

import (
	"maps"
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

	return cloneMapAny(fields, make(map[uintptr]any))
}

// seen maps source references to in-progress clones to preserve cycles
// without aliasing the original.
func cloneValue(v any, seen map[uintptr]any) any {
	switch t := v.(type) {
	case map[string]any:
		return cloneMapAny(t, seen)
	case []any:
		return cloneSliceAny(t, seen)
	}

	switch rv := reflect.ValueOf(v); rv.Kind() {
	case reflect.Map, reflect.Slice, reflect.Array, reflect.Pointer, reflect.Struct:
		return cloneReflectValue(rv, seen).Interface()
	default:
		return v
	}
}

func cloneMapAny(m map[string]any, seen map[uintptr]any) map[string]any {
	if m == nil {
		return nil
	}

	ptr := reflect.ValueOf(m).Pointer()
	if c, ok := seen[ptr]; ok {
		clone, _ := c.(map[string]any)
		return clone
	}

	out := make(map[string]any, len(m))
	seen[ptr] = out

	defer delete(seen, ptr)

	for k, v := range m {
		out[k] = cloneValue(v, seen)
	}

	return out
}

func cloneSliceAny(s []any, seen map[uintptr]any) []any {
	if s == nil {
		return nil
	}

	ptr := reflect.ValueOf(s).Pointer()
	if c, ok := seen[ptr]; ok {
		clone, _ := c.([]any)
		return clone
	}

	out := make([]any, len(s))
	seen[ptr] = out

	defer delete(seen, ptr)

	for i, e := range s {
		out[i] = cloneValue(e, seen)
	}

	return out
}

func cloneReflectValue(rv reflect.Value, seen map[uintptr]any) reflect.Value {
	switch rv.Kind() {
	case reflect.Pointer:
		return clonePointer(rv, seen)
	case reflect.Map:
		return cloneMap(rv, seen)
	case reflect.Slice:
		return cloneSlice(rv, seen)
	case reflect.Array:
		return cloneArray(rv, seen)
	case reflect.Interface:
		return cloneInterface(rv, seen)
	case reflect.Struct:
		return cloneStruct(rv, seen)
	default:
		return rv
	}
}

func clonePointer(rv reflect.Value, seen map[uintptr]any) reflect.Value {
	if rv.IsNil() {
		return rv
	}

	ptr := rv.Pointer()
	if c, ok := seen[ptr]; ok {
		clone, _ := c.(reflect.Value)
		return clone
	}

	out := reflect.New(rv.Type().Elem())
	seen[ptr] = out

	defer delete(seen, ptr)

	out.Elem().Set(cloneReflectValue(rv.Elem(), seen))

	return out
}

func cloneMap(rv reflect.Value, seen map[uintptr]any) reflect.Value {
	if rv.IsNil() {
		return rv
	}

	ptr := rv.Pointer()
	if c, ok := seen[ptr]; ok {
		clone, _ := c.(reflect.Value)
		return clone
	}

	out := reflect.MakeMapWithSize(rv.Type(), rv.Len())
	seen[ptr] = out

	defer delete(seen, ptr)

	for iter := rv.MapRange(); iter.Next(); {
		out.SetMapIndex(iter.Key(), cloneReflectValue(iter.Value(), seen))
	}

	return out
}

func cloneSlice(rv reflect.Value, seen map[uintptr]any) reflect.Value {
	if rv.IsNil() {
		return rv
	}

	ptr := rv.Pointer()
	if c, ok := seen[ptr]; ok {
		clone, _ := c.(reflect.Value)
		return clone
	}

	out := reflect.MakeSlice(rv.Type(), rv.Len(), rv.Len())
	seen[ptr] = out

	defer delete(seen, ptr)

	for i := range rv.Len() {
		out.Index(i).Set(cloneReflectValue(rv.Index(i), seen))
	}

	return out
}

func cloneArray(rv reflect.Value, seen map[uintptr]any) reflect.Value {
	out := reflect.New(rv.Type()).Elem()
	for i := range rv.Len() {
		out.Index(i).Set(cloneReflectValue(rv.Index(i), seen))
	}

	return out
}

func cloneInterface(rv reflect.Value, seen map[uintptr]any) reflect.Value {
	if rv.IsNil() {
		return rv
	}

	out := reflect.New(rv.Type()).Elem()
	out.Set(reflect.ValueOf(cloneValue(rv.Interface(), seen)))

	return out
}

// Copy first because unexported fields cannot be set individually.
func cloneStruct(rv reflect.Value, seen map[uintptr]any) reflect.Value {
	out := reflect.New(rv.Type()).Elem()
	out.Set(rv)

	for i := range rv.NumField() {
		if rv.Type().Field(i).IsExported() {
			out.Field(i).Set(cloneReflectValue(rv.Field(i), seen))
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
	ctx map[string]any
}

func (c *recordCore) Enabled(l zapcore.Level) bool { return l >= c.min }

// With snapshots fields at call time.
func (c *recordCore) With(fields []zapcore.Field) zapcore.Core {
	enc := zapcore.NewMapObjectEncoder()
	maps.Copy(enc.Fields, c.ctx)

	for _, f := range fields {
		f.AddTo(enc)
	}

	return &recordCore{min: c.min, rec: c.rec, ctx: cloneFields(enc.Fields)}
}

func (c *recordCore) Check(e zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if c.Enabled(e.Level) {
		return ce.AddCore(e, c)
	}

	return ce
}

func (c *recordCore) Write(e zapcore.Entry, fields []zapcore.Field) error {
	enc := zapcore.NewMapObjectEncoder()
	maps.Copy(enc.Fields, c.ctx)

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
