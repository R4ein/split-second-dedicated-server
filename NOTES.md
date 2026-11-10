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

- `Friends` (proto 20) method 10 `GetDetailedList(u8 relationship, bool reversed)` →
  List<FriendData>. Polled ~2×/s with (1, false) = friends and (2, true) = incoming
  requests. FriendData (client reader `0xB042D0`):
  `u32 pid, String name, u8 relationship, u32 details, String status`.
  Other methods: 1 `AddFriend(pid, details, msg)`, 3 `AcceptFriendship(pid)`,
  5 `BlackList(pid, details)`, 7 `ClearRelationship(pid)`, each → bool.
- `MatchMaking.GetInvitationsReceived` (10, no args) is polled ~1×/s in the online menus.

## Custom RV services (client setup at 0x9FD710)

Protocol IDs passed to the base client at `0x5EF850`: Competition 15 (0x9FD892),
**RVLeaderboard 101** (0x9FD911), RVPlayer 102 (0x9FD987), RVValidation 111 (0x9FD9BE).
Only the leaderboard stubs exist (0x9FE060/0x9FE1E0/0x9FE370 = methods 1/2/3):

- `1 SubmitStats(bool, List<StatEntry>)` → nothing
- `2 QueryStatsByRange(List<{u32 board, u32 offset, u32 count, bool order, u32 arg}>)`
  → List<cRVLeaderboardStats>
- `3 QueryStatsByPIDs(List<{u32 board, List<u32> pids}>)` → List<cRVLeaderboardStats>

StatEntry/cRVLeaderboardStats share one wire shape (writer `0xA04D30`, reader `0xA04E70`):
`u32, u32, f64, f64, List<Property>`; Property (`0xA04FC0`) =
`u32 id, String name, u32 flags, 6×f64`. On submit the first u32 is the leaderboard id.
In query rows the server sends (pid, rank) there — **unverified against the real game**,
as is the meaning of the query's `order` bool (server: false = highest first).

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
with `FindBySingleID(gid)` + `AcceptInvitation`/`DeclineInvitation`. Invitation layout
`{u32 gid, u32 guest, String msg}` (confirmed in game: the invitee resolves the gid).
Before inviting, the game also sends `Friends` method 1 `(pid, u32 0, String "")`.

## Lobbies and joining

Host: `UpdateGathering(id 0)` (fails, harmless) → `RegisterGathering(ATVGameSession)` →
`Participate(gid)` → `LaunchSession(gid, "")` (empty URL) → `UpdateGathering(gid)`.

Joiner: `FindByType("ATVGameSession")` (or `FindBySingleID` + `AcceptInvitation` for an invite)
→ `Participate(gid)` → `GetParticipantsURLs(gid)` → `NATTraversal.RequestProbeInitiation`
(only when it has stations to probe) → **`SecureConnection.RequestURLs(cid 0, pidHost)`** →
peer-to-peer NetZ connection to the host (not visible to the server).

`pidHost` comes from the gathering header. The game registers **and updates** gatherings
with 0 in `idMyself`, `pidOwner` and `pidHost`, so the server must keep its own values on
`UpdateGathering`. When it returned the client's 0, every joiner called `RequestURLs(0, 0)`,
got nothing, and showed "Lobby no longer exists" within a second. A failed joiner then
sends `UpdateGathering` for the host's gathering (refused, not the owner) and quick match
falls back to creating its own lobby.

`ATVGameSession` = Gathering header (32 bytes + String description, description = host
name, min 2 / max 8) + 40 bytes of game fields (first u32 varies 1/2, likely mode).

The game registers only LAN station URLs (`prudp:/address=192.168.x.x;port=9103;sid=15`).
The server adds each player's public NAT mapping (source of the secure connection) and
public IP + game port; LAN URLs go first only for players behind the same public IP.

## How the game connects to peers (decrypted `JobConnectEndPoint`)

- The NetZ `ConnectionManager` (`0x5C5900`) gets two flags: direct (`+0xC4`) and routing
  (`+0xC5`). For game stations they come from the global mode `[0xD77674]`
  (0 = direct only, 1 = routing only, 2 = both), which is 0 and never written. The RV
  backend connection is created with direct=1, routing=0. **Routing via a server is
  unavailable**; peers must reach each other directly.
- Per URL (`TestCurrentURL`, `0x5D7E70`): if NAT traversal is enabled (`[0xD77A20]`, 0 here)
  and the URL has `RVCID` → NAT traversal; else if `type` bit 1 is clear → plain direct
  resolve; if `type` has bits 1 and 2 (e.g. `type=3`) → `PrepareNATTraversal` first.
- URL keys used by the client (heap strings): `stream`, `sid`, `PID`, `CID`, `type`,
  `XLSPID`, `RVCID`.
- Accepting an invitation does not call `Participate`; `AcceptInvitation` must add the
  player to the gathering.
- **`GetParticipantsURLs` result handling (`0xA29D90`, after the calls at `0xA29C92` join /
  `0xA2925B` accept-invite):** the game walks the returned list and stops at the first URL
  whose `PID` parameter equals its own PID (`[[MatchMakingClient+0xC]+8]`), taking every URL
  before it as stations to probe. It dereferences before checking for the end, so a list
  without the caller's own `PID` makes it run off the end → CRT invalid-parameter abort
  (`0xC000000D`, WER fault offset `0x358615`). The server must tag URLs with `PID` (and
  `RVCID`) and return all participants in join order, host first, including the caller.
- Players on a VPN appear with the VPN exit address; two players on the same exit share one
  public IP and cannot reach each other. A shared virtual LAN (Radmin/ZeroTier/Tailscale)
  works because the game registers every adapter's address.

## AI racers in online races

Races run peer to peer, so the server has no part in them. The game itself supports AI
in networked races: split-screen uses the same NetZ event code.

- `cATVNetEventSlotManager::Host_PopulateSlots` (`0x87B1A0`, called from the host's
  room-state machine at `0x88119E`): if the GameSetup DO's AI flag is 1 (`0x871AD0`, low
  nibble of byte `+0x58`; `[0xD91E4C]` = GameSetup handle), the session master fills
  every free slot up to 8 with AI player DOs. AI updaters are spread across peers
  (`HostMigrateAIUpdatersLoadBalanced`) and migrate when a player leaves.
- The host copies the AI flag into GameSetup from global `[0xD377D4]` (`0x871C30`; high
  nibble from `[0xD377D8]`).
- Event select in the lobby (`0x486FF0`, decrypted code) sets that global:
  game type `[0xD6EE78]` 6 = public lobby → AI off; 7 = private lobby → AI on for event
  modes 0 (Race) and 3 (Survival), off otherwise. Mode names table at `0xD36A68`:
  Race, Elimination, Time Trial, Survival, Air Strike, Air Revenge, Other.
- The private-lobby host's **Game Options** pop-up (`FE_popup`, `[0xD0F474]` = 1) has rows
  Change Vehicle / Change Event / Reset Scores / `TEXT_AI_DIFFICULTY` (On/Off, only for
  modes 0 and 3); leaving the row writes the flag (`0x8719F0`).
- Public-lobby AI would need a runtime patch on the host (e.g. skip the type-6 branch at
  `0x4871F4`); that code is SecuROM-encrypted on disk.

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
