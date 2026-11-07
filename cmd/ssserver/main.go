// Command ssserver is a community replacement for the Quazal Rendez-Vous
// backend that Split/Second (PC) used for online play.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"strconv"
	"time"

	"github.com/R4ein/split-second-dedicated-server/internal/backend"
	"github.com/R4ein/split-second-dedicated-server/internal/kerberos"
	"github.com/R4ein/split-second-dedicated-server/internal/prudp"
)

const usage = `ssserver - Split/Second online server

Usage:
  ssserver [flags]                      run the server
  ssserver [flags] adduser NAME PASS    create an account
  ssserver [flags] passwd NAME PASS     change an account's password
  ssserver [flags] deluser NAME         delete an account
  ssserver [flags] users                list accounts
  ssserver [flags] healthcheck          exit 0 if the local server answers

Every flag can also be set with the environment variable shown in
brackets; a command-line flag wins over the environment.

Flags:
`

func env(name, def string) string {
	if v, ok := os.LookupEnv(name); ok && v != "" {
		return v
	}
	return def
}

func envInt(name string, def int) int {
	if v, err := strconv.Atoi(env(name, "")); err == nil {
		return v
	}
	return def
}

func envBool(name string, def bool) bool {
	if v, err := strconv.ParseBool(env(name, "")); err == nil {
		return v
	}
	return def
}

// resolvePublic accepts an IP address or a hostname (e.g. dynamic DNS) and
// returns the IPv4 address to advertise to players.
func resolvePublic(host string) (string, error) {
	if ip := net.ParseIP(host); ip != nil {
		return ip.String(), nil
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return "", err
	}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			return v4.String(), nil
		}
	}
	return "", fmt.Errorf("%s has no IPv4 address", host)
}

func main() {
	var (
		publicIP   = flag.String("public-ip", env("SS_PUBLIC_IP", "127.0.0.1"), "IP or hostname players use to reach this server [SS_PUBLIC_IP]")
		bind       = flag.String("bind", env("SS_BIND", "0.0.0.0"), "local address to listen on [SS_BIND]")
		authPort   = flag.Int("auth-port", envInt("SS_AUTH_PORT", 31120), "authentication server UDP port; the game always uses 31120 [SS_AUTH_PORT]")
		securePort = flag.Int("secure-port", envInt("SS_SECURE_PORT", 31121), "secure server UDP port [SS_SECURE_PORT]")
		dataDir    = flag.String("data", env("SS_DATA", "data"), "directory for accounts.json [SS_DATA]")
		accessKey  = flag.String("access-key", env("SS_ACCESS_KEY", "3wyEgW4x"), "Quazal access key from the game's live config [SS_ACCESS_KEY]")
		guest      = flag.String("guest-password", env("SS_GUEST_PASSWORD", "h7fyctiuucf"), "password the game uses for its built-in guest account [SS_GUEST_PASSWORD]")
		encCheck   = flag.Bool("encrypt-connect-reply", envBool("SS_ENCRYPT_CONNECT_REPLY", false), "encrypt the secure CONNECT reply; the game expects it plain [SS_ENCRYPT_CONNECT_REPLY]")
		rmcErrors  = flag.Bool("login-errors-as-rmc", envBool("SS_LOGIN_ERRORS_AS_RMC", false), "report login failures as RMC errors instead of a qResult [SS_LOGIN_ERRORS_AS_RMC]")
		verbose    = flag.Bool("v", envBool("SS_VERBOSE", false), "log every packet and message [SS_VERBOSE]")
	)
	flag.Usage = func() {
		fmt.Fprint(os.Stderr, usage)
		flag.PrintDefaults()
	}
	flag.Parse()
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	if flag.Arg(0) == "healthcheck" {
		os.Exit(healthcheck(*authPort, *accessKey))
	}

	store, err := backend.OpenStore(*dataDir)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}

	if args := flag.Args(); len(args) > 0 {
		os.Exit(admin(store, args))
	}

	pub, err := resolvePublic(*publicIP)
	if err != nil {
		log.Fatalf("public address %q: %v", *publicIP, err)
	}
	if ip := net.ParseIP(pub); ip.IsLoopback() && *bind != "127.0.0.1" {
		log.Printf("WARNING: public IP is %s; players on other machines cannot reach the secure server. Set -public-ip / SS_PUBLIC_IP.", pub)
	}

	settings := &prudp.Settings{AccessKey: *accessKey, Verbose: *verbose}
	b := backend.New(backend.Config{
		PublicIP: pub, AuthPort: *authPort, SecurePort: *securePort,
		GuestSecret: *guest, EncryptCheck: *encCheck, LoginErrorsAsRMC: *rmcErrors,
	}, store, settings)

	log.Printf("Split/Second server starting; secure URL %s", b.SecureURL())
	errc := make(chan error, 2)
	go func() { errc <- b.Auth.ListenAndServe(fmt.Sprintf("%s:%d", *bind, *authPort)) }()
	go func() { errc <- b.Secure.ListenAndServe(fmt.Sprintf("%s:%d", *bind, *securePort)) }()
	log.Fatal(<-errc)
}

// healthcheck sends a PRUDP SYN to the local auth server and expects a
// SYN-ACK. Used by the container health check (no shell in the image).
func healthcheck(port int, accessKey string) int {
	c, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck:", err)
		return 1
	}
	defer c.Close()
	syn := &prudp.Packet{Src: 0x3f, Dst: 0x31, Type: prudp.TypeSyn, Flags: prudp.FlagNeedAck}
	if _, err := c.Write(syn.Encode(prudp.Layout3x5, prudp.KeySum(accessKey))); err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck:", err)
		return 1
	}
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1500)
	n, err := c.Read(buf)
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck: no reply:", err)
		return 1
	}
	if p, err := prudp.Decode(buf[:n], prudp.Layout3x5); err != nil || p.Type != prudp.TypeSyn || p.Flags&prudp.FlagAck == 0 {
		fmt.Fprintln(os.Stderr, "healthcheck: unexpected reply")
		return 1
	}
	fmt.Println("ok")
	return 0
}

func admin(store *backend.Store, args []string) int {
	need := func(n int) bool {
		if len(args) != n {
			flag.Usage()
			return false
		}
		return true
	}
	switch args[0] {
	case "adduser":
		if !need(3) {
			return 2
		}
		a, err := store.Create(args[1], kerberos.InitialHash([]byte(args[2])), "", 0)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		fmt.Printf("created %s (pid %d)\n", a.Name, a.PID)
	case "passwd":
		if !need(3) {
			return 2
		}
		if err := store.SetPassword(args[1], kerberos.InitialHash([]byte(args[2]))); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		fmt.Println("password changed")
	case "deluser":
		if !need(2) {
			return 2
		}
		if err := store.Delete(args[1]); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		fmt.Println("deleted")
	case "users":
		l := store.List()
		sort.Slice(l, func(i, j int) bool { return l[i].PID < l[j].PID })
		for _, a := range l {
			fmt.Printf("%6d  %-24s created %s\n", a.PID, a.Name, a.Created.Format("2006-01-02"))
		}
	default:
		flag.Usage()
		return 2
	}
	return 0
}
