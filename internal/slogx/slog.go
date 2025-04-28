// Package slogx provides additional handlers for the [log/slog] package.
package slogx

import (
	"context"
	"errors"
	"log/slog"
)

type MultiHandler []slog.Handler

func (h MultiHandler) Enabled(ctx context.Context, l slog.Level) bool {
	for i := range h {
		if h[i].Enabled(ctx, l) {
			return true
		}
	}
	return false
}

func (h MultiHandler) Handle(ctx context.Context, r slog.Record) error {
	var errs []error
	for i := range h {
		if h[i].Enabled(ctx, r.Level) {
			if err := h[i].Handle(ctx, r.Clone()); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

func (h MultiHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	handlers := make([]slog.Handler, 0, len(h))
	for i := range h {
		handlers = append(handlers, h[i].WithAttrs(attrs))
	}
	return MultiHandler(handlers)
}

func (h MultiHandler) WithGroup(name string) slog.Handler {
	handlers := make([]slog.Handler, 0, len(h))
	for i := range h {
		handlers = append(handlers, h[i].WithGroup(name))
	}
	return MultiHandler(handlers)
}

type FilterHandler struct {
	handler slog.Handler
	filter  func(r slog.Record) bool
}

func NewFilterHandler(handler slog.Handler, filter func(r slog.Record) bool) FilterHandler {
	return FilterHandler{
		handler: handler,
		filter:  filter,
	}
}

func (h FilterHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.handler.Enabled(ctx, l)
}

func (h FilterHandler) Handle(ctx context.Context, r slog.Record) error {
	if h.filter(r) {
		return h.handler.Handle(ctx, r)
	}
	return nil
}

func (h FilterHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return FilterHandler{
		handler: h.handler.WithAttrs(attrs),
		filter:  h.filter,
	}
}

func (h FilterHandler) WithGroup(name string) slog.Handler {
	return FilterHandler{
		handler: h.handler.WithGroup(name),
		filter:  h.filter,
	}
}
