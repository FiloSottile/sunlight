// Package reused allows tracking connection reuse in HTTP requests.
package reused

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync/atomic"
)

type connGlobalContextKey struct{}

type reusedConnContextKey struct{}

var ContextKey = reusedConnContextKey{}

func ConnContext(ctx context.Context, c net.Conn) context.Context {
	return context.WithValue(ctx, connGlobalContextKey{}, &atomic.Bool{})
}

func LabelFromContext(ctx context.Context) string {
	if r, ok := ctx.Value(ContextKey).(bool); ok {
		return fmt.Sprintf("%t", r)
	}
	return ""
}

func NewHandler(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if connGlobal, ok := r.Context().Value(connGlobalContextKey{}).(*atomic.Bool); ok {
			reused := connGlobal.Swap(true)
			r = r.WithContext(context.WithValue(r.Context(), ContextKey, reused))
		}
		handler.ServeHTTP(w, r)
	})
}
