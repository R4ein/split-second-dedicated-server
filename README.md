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
| Creating a private lobby (host side) | Works: lobby opens, waits for players |
| Friends list | Stub: always empty |
| Joining another player's lobby, Quick Match, invites | Implemented server-side, **not yet tested with two players** |
| Peer-to-peer race connection across the internet (NAT traversal) | Not implemented yet |
| Leaderboards / rankings / Competition / RV custom protocols | Not implemented (calls are logged) |

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

Accounts live in the named volume `split-second_ssserver-data` and survive
rebuilds. To update after pulling new code: `git pull && docker compose up -d --build`.

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

The game uses UDP port 9103 on each PC for player-to-player traffic. Until
NAT traversal is implemented, the player hosting a lobby will probably need
to forward UDP 9103 on their router for races (untested).

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
