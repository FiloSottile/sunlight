package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"log"
	"os"
	"strconv"
	"strings"

	"crawshaw.io/sqlite"
	"filippo.io/sunlight"
	"github.com/schollz/progressbar/v3"
	"golang.org/x/mod/sumdb/tlog"
)

func main() {
	conn, err := sqlite.OpenConn(os.Args[1], 0)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	if err := ExecScript(conn, `
		CREATE TABLE IF NOT EXISTS names (name TEXT PRIMARY KEY) WITHOUT ROWID;
		PRAGMA journal_mode = WAL;
		PRAGMA synchronous = OFF;
		PRAGMA cache_size = 100000;
		PRAGMA temp_store = MEMORY;
	`); err != nil {
		log.Fatal(err)
	}

	insStmt, err := conn.Prepare("INSERT OR IGNORE INTO names (name) VALUES ($1);")
	if err != nil {
		log.Fatal(err)
	}

	root, err := os.OpenRoot(os.Args[2])
	if err != nil {
		log.Fatal(err)
	}

	checkpoint, err := root.ReadFile("checkpoint")
	if err != nil {
		log.Fatal(err)
	}
	_, rest, _ := strings.Cut(string(checkpoint), "\n")
	size, _, _ := strings.Cut(rest, "\n")
	end, err := strconv.ParseInt(size, 10, 64)
	if err != nil {
		log.Fatal(err)
	}

	bar := progressbar.Default(end)
	for n := range end / 256 {
		tile := sunlight.TilePath(tlog.Tile{H: 8, L: -2, N: n, W: 256})
		data, err := root.ReadFile(tile)
		if os.IsNotExist(err) {
			continue // Skip missing tiles.
		}
		if err != nil {
			log.Fatal(err)
		}
		r, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			log.Fatal(err)
		}
		d := json.NewDecoder(r)
		for {
			var entry struct {
				DNS []string
			}
			if err := d.Decode(&entry); err != nil {
				if err == io.EOF {
					break
				}
				log.Fatal(err)
			}
			for _, name := range entry.DNS {
				if err := insStmt.Reset(); err != nil {
					log.Fatal(err)
				}
				insStmt.SetText("$1", name)
				if _, err := insStmt.Step(); err != nil {
					log.Fatal(err)
				}
			}
			bar.Add(1)
		}
	}

	if err := ExecScript(conn, `
		PRAGMA sycnhronous = NORMAL;
		PRAGMA journal_mode = MEMORY;
		VACUUM;
	`); err != nil {
		log.Fatal(err)
	}
}

func ExecScript(conn *sqlite.Conn, queries string) (err error) {
	for {
		queries = strings.TrimSpace(queries)
		if queries == "" {
			break
		}
		var stmt *sqlite.Stmt
		var trailingBytes int
		stmt, trailingBytes, err = conn.PrepareTransient(queries)
		if err != nil {
			return err
		}
		usedBytes := len(queries) - trailingBytes
		queries = queries[usedBytes:]
		_, err := stmt.Step()
		stmt.Finalize()
		if err != nil {
			return err
		}
	}
	return nil
}
