package tlogx_test

import (
	"fmt"
	"testing"

	"filippo.io/sunlight/internal/tlogx"
	"golang.org/x/mod/sumdb/tlog"
)

func TestNewTilesForSize(t *testing.T) {
	for _, tt := range []struct {
		old, new int64
		want     int
	}{
		{1, 1, 0},
		{100, 101, 1},
		{1023, 1025, 3},
		{1024, 1030, 1},
		{1030, 2000, 1},
		{1030, 10000, 10},
		{49516517, 49516586, 3},
	} {
		t.Run(fmt.Sprintf("%d-%d", tt.old, tt.new), func(t *testing.T) {
			tiles := tlogx.NewTilesForSize(10, tt.old, tt.new)
			if got := len(tiles); got != tt.want {
				t.Errorf("got %d, want %d", got, tt.want)
				for _, tile := range tiles {
					t.Logf("%+v", tile)
				}
			}
			more := tlog.NewTiles(10, tt.old, tt.new)
			for _, tt := range tiles {
				var ok bool
				for _, mt := range more {
					if tt == mt {
						ok = true
					}
				}
				if !ok {
					t.Errorf("extra tile %+v", tt)
				}
			}
		})
	}
}
