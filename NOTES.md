# Protocol notes (Split/Second PC, Quazal Rendez-Vous ~2010)

Findings from the game executable and live traffic. Addresses are for the
Steam build of `SplitSecond.exe` (image base 0x400000).

## Endpoints

Chosen in `0xA25970` by a global build flag:

| Env | Host | Port | Access key |
|---|---|---|---|
| live | `splitsecpclive.quazal.net` | 31120 (0x7990) | `3wyEgW4x` |
| dev A | `splitsecpcdeva.quazal.net` | 10920 | `gDg59xT` |
| dev B | `splitsecpcdevb.quazal.net` | 10950 | `gDg59xT` |

Public DNS resolves the live host to 127.0.0.1. The client's own PRUDP
socket uses UDP port 9103 for every connection (auth, secure, peers).

## PRUDP v0

- Type/flags byte: type = low 3 bits, flags = high 5 bits (ACK 1, REL 2, NEEDACK 4, SIZE 8).
- Checksum: `(sum(access key bytes) + bytes of u32 word-sum + trailing bytes) & 0xFF`; key sum 0xD2.
- Payload: RC4 key `CD&ML`, fresh cipher per packet, then a compression byte (0 = stored, else zlib).
- Client sends SYN seq 0, CONNECT seq 1, DATA from seq 2; server's own reliable seq starts at 1.
- Vports: client 0x3F → server 0x31. Client pings every 10 s and disconnects after ~30 s of silence.

## Login (TicketGranting, proto 10)

- `Login(name)` result: qResult, pid, Buffer ticket, RVConnectionData (String regularURL,
  List<u8> special, String specialURL), String msg.
- Failures must be the **qResult inside a successful RMC response**. An RMC-level error is
  shown as a generic "Connection to the game server failed".
- `0x80030064` InvalidUsername makes the UI offer "Account does not exist. Create?".
  RendezVous error numbering matches NEX (decoded at `0x5EAC70`).
- **specialURL must be an empty string**. Any non-empty value makes the client try to connect
  to it after the secure connection, and hang for 30 s.
- Then `RequestTicket(pid, 2)` before connecting to the secure server.

## Keys and tickets

- MD5KeyDerivation (`vtable 0xBE3B6C`): 65000 base iterations, modulus 1024.
- Player key = MD5^(65000 + pid % 1024)(password).
- `CreateAccount` sends `hex(MD5^65000(password))` (lowercase) as the key string; the server
  derives the final key with `pid % 1024` more MD5 rounds.
- Ticket = RC4(userKey, sessionKey[16] | u32 targetPID | Buffer serverTicket) + HMAC-MD5(userKey, ct).

## Secure connection

- CONNECT payload: `Buffer(serverTicket) + Buffer(RC4(sessionKey, pid|cid|check) + HMAC)`.
- CONNECT ack payload: `Buffer(u32 check+1)`, **not encrypted** (see `0x5F0228`/`0x5F0340`).
- `Register(List<StationURL>)` → qResult, cid, public URL. Client registers its LAN addresses.

## Account creation flow

Login fails with InvalidUsername → user confirms → login as `guest` with password
`h7fyctiuucf` (pid 100) → secure connect → `AccountManagement.CreateAccount(name,
hex initial hash, groups=32, email="qwerty@keyboard.com")` → logout → normal login.

## After login

- `Friends` (proto 20) method 10 `(u8 relationship=2, bool reversed=1)` is polled every
  ~0.5 s until it succeeds; answer with an empty list.

## Private lobby (host)

`UpdateGathering(id 0)` (fails, harmless) → `RegisterGathering(ATVGameSession)` →
`Participate(gid)` → `LaunchSession(gid, "")` (empty URL) → `UpdateGathering(gid)`.

`ATVGameSession` = Gathering header (32 bytes + String description, description = host
name, min 2 / max 8) + 40 bytes of game fields ending in `0xDEADBEEF`.

## Not yet seen / to do

- Joining: expected Find*/Participate/GetParticipantsURLs/SecureConnection.RequestURLs.
- NAT traversal (`NATTraversalProtocolClient`), probably needed for internet races.
- Game-specific protocols: `RVLeaderboardProtocolClient`, `RVPlayerProtocolClient`,
  `RVValidationProtocolClient`, `CompetitionProtocolClient`, Messaging/MessageDelivery.

## Reverse-engineering tools

SecuROM encrypts parts of `.text` on disk (login, crypto, error tables). They are
decrypted in memory while the game runs.

- `tools/memdump`: read-only copy of the running game's image:
  `memdump <pid> 400000 1DB7000 out.bin`. Keep dumps private; never redistribute.
- `tools/ssre`: strings, xrefs, callers, data refs, RTTI vtables, disassembly.
  Set `SSRE_MEM=out.bin` to analyse the in-memory image instead of the file.
