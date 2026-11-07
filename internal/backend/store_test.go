package backend

import (
	"bytes"
	"testing"

	"github.com/R4ein/split-second-dedicated-server/internal/kerberos"
)

// An admin command (separate process) and the running server share the
// accounts file; each must see the other's changes.
func TestStoreSeesExternalChanges(t *testing.T) {
	dir := t.TempDir()
	server, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(server.ServerKey(), admin.ServerKey()) {
		t.Fatal("second store generated a new server secret")
	}

	a, err := admin.Create("Racer", kerberos.InitialHash([]byte("pw")), "", 0)
	if err != nil {
		t.Fatal(err)
	}
	got := server.ByName("racer")
	if got == nil || got.PID != a.PID {
		t.Fatalf("server did not pick up the new account: %+v", got)
	}

	// The server's next account must not reuse the admin's PID.
	b, err := server.Create("Other", kerberos.InitialHash([]byte("pw")), "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if b.PID == a.PID {
		t.Fatal("PID reused")
	}
	if admin.ByName("other") == nil {
		t.Fatal("admin did not see the server's account")
	}
	if err := admin.Delete("racer"); err != nil {
		t.Fatal(err)
	}
	if server.ByName("racer") != nil {
		t.Fatal("server still sees a deleted account")
	}
}
