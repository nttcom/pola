// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package logger

import (
	"maps"
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
	e.Fields = maps.Clone(e.Fields)
	return e
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

	c.rec.add(Entry{
		Level:   levelFromZap(e.Level),
		Message: e.Message,
		Fields:  enc.Fields,
	})

	return nil
}

func (c *recordCore) Sync() error { return nil }
