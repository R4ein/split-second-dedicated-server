# Split/Second community server

A replacement for the Quazal Rendez-Vous backend that the PC version of
Split/Second (Steam app 297860) used for online play before Disney shut it
down. Single Go binary with no third-party dependencies; accounts are kept
in one JSON file.

## Status

| Feature | State |
|---|---|
| Login, in-game account creation ("Account does not exist. Create?") | Works with the real game |
| Secure connection, station URL registration | Works |
| Creating lobbies, finding other players' lobbies | Works with two players |
| Invites by name (lobby INVITE slot), online status | Works: invite arrives and is accepted |
| Joining a lobby / starting a race between two PCs | Depends on the players' networks, see below |
| Friends list (requests, accept, blacklist, online status) | Implemented, stored in `friends.json` |
| Player statistics / leaderboards / rankings | Implemented, stored in `stats.json`; row order untested against the real game |
| Competition / RVPlayer / RVValidation protocols | Not implemented (never seen called; calls are logged) |

The game polls the friends list and pending invites continuously; those calls are
only logged with `SS_VERBOSE=true`.

Friend requests come from the in-game friends screen (and inviting someone to a
lobby also sends one). The other player accepts from their friends screen.
Leaderboard rows are built from the stats each game submits after races; the
server ranks players per leaderboard and answers the game's range and
by-player queries.

## Deploy with Docker Compose

On the VM (Docker Engine with the Compose v2 plugin):

```bash
git clone git@github.com:R4ein/split-second-dedicated-server.git
cd split-second-dedicated-server
cp .env.example .env
nano .env                  # set SS_PUBLIC_IP to the VM's public IP or DNS name
docker compose up -d --build
docker compose logs -f
```

Then allow **UDP 31120 and 31121** inbound in the VM's firewall and any
cloud security group. Both host ports must stay 31120/31121: the game always
dials 31120, and the server tells the game which secure port to use.

`docker compose ps` shows the container as `healthy` once the server answers
a PRUDP handshake on 31120.

Accounts, friend lists and leaderboard stats live in the named volume
`split-second_ssserver-data` (`accounts.json`, `friends.json`, `stats.json`)
and survive rebuilds. To update after pulling new code: `git pull && docker compose up -d --build`.

### Account administration

These run in a one-off container against the same volume. They are safe
while the server is running; it picks up changes automatically.

```bash
docker compose run --rm ssserver users                  # list accounts
docker compose run --rm ssserver adduser NAME PASSWORD  # create an account
docker compose run --rm ssserver passwd NAME PASSWORD   # reset a password
docker compose run --rm ssserver deluser NAME           # delete an account
```

Players normally create their own accounts in the game, so `adduser` is
only needed for special cases. Passwords are never stored: the server keeps
only the key the game itself derives (MD5 iterated 65000+ times).

### Configuration

Set in `.env` (Compose) or as environment variables / flags (`ssserver -h`):

| Variable | Default | Meaning |
|---|---|---|
| `SS_PUBLIC_IP` | `127.0.0.1` | IP or hostname players reach the server at (**required** in Compose) |
| `SS_VERBOSE` | `false` | Log every packet and message. Logs then contain raw traffic; keep them private |
| `SS_DATA` | `/data` in the image | Directory holding `accounts.json` |
| `SS_AUTH_PORT` / `SS_SECURE_PORT` | `31120` / `31121` | UDP ports; leave as is |

## Connect the game (every player)

The game always contacts `splitsecpclive.quazal.net`. Public DNS currently
resolves that name to `127.0.0.1`, so each player points it at the server
with one line in `C:\Windows\System32\drivers\etc\hosts` (open Notepad as
administrator):

```
203.0.113.10 splitsecpclive.quazal.net
```

Use the VM's public IP. Then start the game, choose **Online**, type a new
username and password, and confirm **Create** when it says the account does
not exist. Use a password you don't use anywhere else.

## How players connect to each other (read this if joining fails)

The server only introduces players. The race itself runs **directly between
the players' PCs** over UDP port 9103; this build of the game has no way to
relay race traffic through a server. When a player joins a lobby, the server
hands their game a list of addresses for the other players, and the game
tries them one by one:

1. an address on a virtual LAN both players are on (Radmin VPN, Hamachi,
   Tailscale, ZeroTier, ...)
2. the other player's public address, with NAT hole punching arranged by
   the server
3. the other player's home-LAN address (only if both share a public IP)

What that means in practice:

- **No VPN, normal home routers:** should work through hole punching. If a
  router is strict, forward UDP 9103 to the PC of the player who hosts.
- **VPN / proxy / anti-censorship tool:** the server sees the VPN's address,
  not the player's. Two players behind VPNs (especially the same VPN
  provider or exit) **cannot reach each other**. Either exclude
  `SplitSecond.exe` from the VPN (split tunnelling), or use the virtual-LAN
  option below.
- **Virtual LAN (works around VPNs and strict routers):** all players join
  the same Radmin VPN / ZeroTier / Tailscale network and keep the hosts-file
  line pointing at the VM. The game reports its virtual-LAN address
  automatically and the server puts it first, so no other setup is needed.
  Make sure Windows Firewall allows `SplitSecond.exe` on that network.

Each address the game cannot reach costs it a timeout, so a join can take a
while before it succeeds or fails.

## Without Docker

```bash
go build -o ssserver ./cmd/ssserver        # Go 1.22 or newer
./ssserver -public-ip 203.0.113.10 -data ./data
```

Cross-compile for a Linux VM from another OS:
`GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o ssserver ./cmd/ssserver`

### Local testing

Because public DNS sends the game to `127.0.0.1`, a server running on the
same PC as the game needs no hosts-file change:

```bash
go run ./cmd/ssserver -bind 127.0.0.1 -v
```

## Layout

- `cmd/ssserver`: entry point, admin commands, health check
- `internal/prudp`: Quazal PRUDP v0 transport (checksums, RC4, reliability, fragments)
- `internal/rmc`: RMC framing and DDL types
- `internal/kerberos`: key derivation and ticket crypto
- `internal/backend`: TicketGranting, SecureConnection, AccountManagement, Friends, MatchMaking
- `tools/`: reverse-engineering helpers in a separate Go module (Windows-only memdump);
  not part of the server or the image. See `NOTES.md`.
