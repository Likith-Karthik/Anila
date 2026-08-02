package probe

import (
	"context"
	"syscall"
	"testing"
)

func TestClassifyNetworkError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want ErrorKind
	}{
		{"cancelled", context.Canceled, ErrorCancelled},
		{"timeout", context.DeadlineExceeded, ErrorConnectionTimeout},
		{"refused", syscall.ECONNREFUSED, ErrorConnectionRefused},
		{"network unreachable", syscall.ENETUNREACH, ErrorNetworkUnreachable},
		{"other", syscall.EIO, ErrorNetwork},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ClassifyNetworkError("test", tt.err); got.Kind != tt.want {
				t.Fatalf("ClassifyNetworkError() = %+v, want %s", got, tt.want)
			}
		})
	}
}
