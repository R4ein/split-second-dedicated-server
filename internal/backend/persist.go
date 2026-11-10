package backend

import (
	"encoding/json"
	"errors"
	"log"
	"os"
)

// loadJSON reads a JSON data file into v. A missing file is not an error:
// the caller keeps its zero value and the file appears on the first save.
func loadJSON(path string, v any) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err == nil {
		err = json.Unmarshal(b, v)
	}
	if err != nil {
		log.Printf("[store] load %s: %v (starting empty)", path, err)
	}
}

// saveJSON writes v atomically. Marshal v (or a snapshot of it) while
// holding its lock; the file write itself needs no lock.
func saveJSON(path string, v any) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		log.Printf("[store] save %s: %v", path, err)
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err == nil {
		err = os.Rename(tmp, path)
	} else {
		os.Remove(tmp)
	}
	if err != nil {
		log.Printf("[store] save %s: %v", path, err)
	}
}
