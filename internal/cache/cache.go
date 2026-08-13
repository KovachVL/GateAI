package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"

	"github.com/KovachVL/GateAI/internal/verdict"
)

type Cache struct {
	mu      sync.Mutex
	path    string
	entries map[string]verdict.Verdict
	dirty   bool
}

func Key(fingerprint, model, effort, promptVersion string, skeptic bool) string {
	h := sha256.New()
	for _, p := range []string{fingerprint, model, effort, promptVersion} {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	if skeptic {
		h.Write([]byte("skeptic"))
	}
	return hex.EncodeToString(h.Sum(nil))[:32]
}

func Open(path string) (*Cache, error) {
	c := &Cache{path: path, entries: map[string]verdict.Verdict{}}
	if path == "" {
		return c, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return c, nil
		}
		return nil, err
	}

	_ = json.Unmarshal(data, &c.entries)
	return c, nil
}

func (c *Cache) Get(key string) (verdict.Verdict, bool) {
	if c == nil || c.path == "" {
		return verdict.Verdict{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.entries[key]
	if ok {
		v.Cached = true
	}
	return v, ok
}

func (c *Cache) Put(key string, v verdict.Verdict) {
	if c == nil || c.path == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	v.Cached = false
	c.entries[key] = v
	c.dirty = true
}

func (c *Cache) Save() error {
	if c == nil || c.path == "" || !c.dirty {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(c.path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(c.entries, "", "  ")
	if err != nil {
		return err
	}
	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, c.path)
}
