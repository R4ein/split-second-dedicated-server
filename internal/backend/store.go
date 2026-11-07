// Package backend implements the Rendez-Vous services Split/Second talks to.
package backend

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/R4ein/split-second-dedicated-server/internal/kerberos"
)

const (
	PIDAuthServer   uint32 = 1
	PIDSecureServer uint32 = 2
	PIDGuest        uint32 = 100
	firstUserPID    uint32 = 1000
)

// Account is a persisted player account. Only the derived Kerberos key is
// stored, never the password itself.
type Account struct {
	PID     uint32    `json:"pid"`
	Name    string    `json:"name"`
	Key     string    `json:"key"` // hex DeriveKey(password, pid)
	Email   string    `json:"email,omitempty"`
	Groups  uint32    `json:"groups,omitempty"`
	Created time.Time `json:"created"`
}

type storeFile struct {
	NextPID      uint32              `json:"next_pid"`
	ServerSecret string              `json:"server_secret"`
	Accounts     map[string]*Account `json:"accounts"`
}

// Store keeps accounts in a JSON file. It re-reads the file whenever it
// changes on disk, so admin commands can run while the server is up.
type Store struct {
	path    string
	mu      sync.Mutex
	f       storeFile
	modTime time.Time
	size    int64
}

func OpenStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &Store{path: filepath.Join(dir, "accounts.json")}
	if err := s.load(); errors.Is(err, os.ErrNotExist) {
		secret := make([]byte, 16)
		rand.Read(secret)
		s.f = storeFile{NextPID: firstUserPID, ServerSecret: hex.EncodeToString(secret), Accounts: map[string]*Account{}}
		return s, s.save()
	} else if err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) load() error {
	st, err := os.Stat(s.path)
	if err != nil {
		return err
	}
	b, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	var f storeFile
	if err := json.Unmarshal(b, &f); err != nil {
		return err
	}
	if f.Accounts == nil {
		f.Accounts = map[string]*Account{}
	}
	s.f, s.modTime, s.size = f, st.ModTime(), st.Size()
	return nil
}

// refresh reloads the file if another process changed it. Call with s.mu held.
func (s *Store) refresh() {
	st, err := os.Stat(s.path)
	if err != nil || (st.ModTime().Equal(s.modTime) && st.Size() == s.size) {
		return
	}
	if err := s.load(); err != nil {
		log.Printf("[store] reload %s: %v (keeping previous data)", s.path, err)
		return
	}
	log.Printf("[store] reloaded %s (%d accounts)", s.path, len(s.f.Accounts))
}

func (s *Store) save() error {
	b, err := json.MarshalIndent(&s.f, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return err
	}
	if st, err := os.Stat(s.path); err == nil {
		s.modTime, s.size = st.ModTime(), st.Size()
	}
	return nil
}

// ServerKey is the secret the secure server uses to read its own tickets.
func (s *Store) ServerKey() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refresh()
	b, _ := hex.DecodeString(s.f.ServerSecret)
	return b
}

var ErrExists = errors.New("account already exists")

func validName(name string) bool {
	if len(name) < 1 || len(name) > 32 {
		return false
	}
	for _, c := range name {
		if c < 0x21 || c > 0x7e {
			return false
		}
	}
	return true
}

// Create registers an account from its 16-byte initial hash (see
// kerberos.InitialHash).
func (s *Store) Create(name string, initialHash []byte, email string, groups uint32) (*Account, error) {
	if !validName(name) {
		return nil, errors.New("invalid account name")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refresh()
	k := strings.ToLower(name)
	if _, ok := s.f.Accounts[k]; ok || k == "guest" {
		return nil, ErrExists
	}
	pid := s.f.NextPID
	s.f.NextPID++
	a := &Account{PID: pid, Name: name, Email: email, Groups: groups, Created: time.Now().UTC(),
		Key: hex.EncodeToString(kerberos.DeriveFromInitial(initialHash, pid))}
	s.f.Accounts[k] = a
	return a, s.save()
}

func (s *Store) SetPassword(name string, initialHash []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refresh()
	a, ok := s.f.Accounts[strings.ToLower(name)]
	if !ok {
		return errors.New("no such account")
	}
	a.Key = hex.EncodeToString(kerberos.DeriveFromInitial(initialHash, a.PID))
	return s.save()
}

// ParseKey decodes the key string the game sends in account calls: the
// lowercase hex of the initial hash. Anything else is treated as a plain
// password.
func ParseKey(key string) []byte {
	if b, err := hex.DecodeString(key); err == nil && len(b) == 16 {
		return b
	}
	return kerberos.InitialHash([]byte(key))
}

func (s *Store) Delete(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refresh()
	k := strings.ToLower(name)
	if _, ok := s.f.Accounts[k]; !ok {
		return errors.New("no such account")
	}
	delete(s.f.Accounts, k)
	return s.save()
}

func (s *Store) ByName(name string) *Account {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refresh()
	if a, ok := s.f.Accounts[strings.ToLower(name)]; ok {
		c := *a
		return &c
	}
	return nil
}

func (s *Store) ByPID(pid uint32) *Account {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refresh()
	for _, a := range s.f.Accounts {
		if a.PID == pid {
			c := *a
			return &c
		}
	}
	return nil
}

func (s *Store) List() []Account {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refresh()
	out := make([]Account, 0, len(s.f.Accounts))
	for _, a := range s.f.Accounts {
		out = append(out, *a)
	}
	return out
}

func (a *Account) KeyBytes() []byte {
	b, _ := hex.DecodeString(a.Key)
	return b
}
