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

- `Friends` (proto 20) method 10 `(u8 relationship=2, bool reversed=1)` → one list. Polled
  ~2×/s for the whole online session whether it succeeds or not; answer with an empty list.
- `MatchMaking.GetInvitationsReceived` (10, no args) is polled ~1×/s in the online menus.

## Client RPC stubs (decrypted image)

Every stub calls `BeginRequest 0x5C0DA0(msg, [this+0x18]=protocol, 1)`, then
`0x5CDDD0(msg, methodID)`, writes arguments (`0x5B58D0(ptr, size, count)` raw,
`0x5B5B60` bool, `0x5B7AB0` String, `0x5B7DA0` StationURL, `0x5F1CC0` List<StationURL>),
registers one pointer per return value with `0x5B4860`, and sends via `0x5CE170`.

| Stub range | Protocol | Methods (args → number of return values) |
|---|---|---|
| 0x5F05B0–0x5F1F20 | TicketGranting / SecureConnection | Login 1, LoginEx 2, RequestTicket 3; Register 1, RegisterEx 4 |
| 0xAFFA30–0xB00580 | AccountManagement | 1 Create, 4 ChangePassword, **18 GetStatus(u32)→String**, 21, 23, 24, 26 |
| 0xB03880–0xB03D70 | Friends | 1 (u32,u32,String), 3 (u32), 5 (u32,u32), 7 (u32), 10 (u8,bool)→list |
| 0xB055D0–0xB069D0 | MatchMaking | 1, 2, 4, **5 Invite(u32, List<u32>, String)**, 6 Accept, 7 Decline, 10, 11, 12, 16, 17, 18, 21 (→2), 26, 30 |
| 0xB09F30, 0xB0A05C | NATTraversal | 1 (List<URL>), 3 (List<URL>, URL); client serves 2 InitiateProbe (0xB09E80) |
| 0x9FE060–0x9FEBB0 | game-specific RV protocols | not identified yet |

## Invites

INVITE slot in a lobby: `TicketGranting.GetPID(name)` **on the secure connection** →
`AccountManagement.GetStatus(pid)`; the game only invites if the string contains `"Online"`
(`0xA25CC0`) → `MatchMaking.Invite`. The invitee polls `GetInvitationsReceived` and answers
with `AcceptInvitation`/`DeclineInvitation`. Invitation layout assumed `{u32 gid, u32 guest,
String msg}` (its DDL code is COMDAT-folded, unverified).

## Lobbies and joining

Host: `UpdateGathering(id 0)` (fails, harmless) → `RegisterGathering(ATVGameSession)` →
`Participate(gid)` → `LaunchSession(gid, "")` (empty URL) → `UpdateGathering(gid)`.

Joiner: `FindByType("ATVGameSession")` → `Participate(gid)` → `GetParticipantsURLs(gid)` →
peer-to-peer NetZ connection to the host (not visible to the server).

`ATVGameSession` = Gathering header (32 bytes + String description, description = host
name, min 2 / max 8) + 40 bytes of game fields (first u32 varies 1/2, likely mode).

The game registers only LAN station URLs (`prudp:/address=192.168.x.x;port=9103;sid=15`).
The server adds each player's public NAT mapping (source of the secure connection) and
public IP + game port; LAN URLs go first only for players behind the same public IP.

## Not yet seen / to do

- Whether races start between two networks (NAT traversal relay is implemented, untested).
- Game-specific protocols: `RVLeaderboardProtocolClient`, `RVPlayerProtocolClient`,
  `RVValidationProtocolClient`, `CompetitionProtocolClient`, Messaging/MessageDelivery.

## Reverse-engineering tools

SecuROM encrypts parts of `.text` on disk (login, crypto, error tables). They are
decrypted in memory while the game runs.

- `tools/memdump`: read-only copy of the running game's image:
  `memdump <pid> 400000 1DB7000 out.bin`. Keep dumps private; never redistribute.
- `tools/ssre`: strings, xrefs, callers, data refs, RTTI vtables, disassembly.
  Set `SSRE_MEM=out.bin` to analyse the in-memory image instead of the file.
