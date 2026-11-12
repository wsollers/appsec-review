# Fix-pair corpus candidates (T-067)

Status: research output of 2026-11-11 for T-067 in [`../TODO.md`](../TODO.md). **This is a candidate list
produced from public web pages. Nothing was cloned, downloaded as a tree, built or pinned, and no pair is a
scoring key yet.** Choosing pairs, acquiring and pinning targets, and splitting the public corpus from the
private holdout are owned by the repository owner
([`../architecture/finding-metrics.md`](../architecture/finding-metrics.md) section 6 and decision 13).

## 1. Purpose

T-067 needs published, fixed vulnerabilities in open game, engine and game-networking code written in C or
C++, each as a pre-fix and a post-fix revision, so that recall and `fixed` versus `still_present` can be
measured on real defects. This document lists candidates whose advisory, fixing commit, parent commit, touched
file and lines, weakness class and licence were each read on a public page, and separately lists leads where
one of those could not be confirmed.

The draft corpus file is
[`test/acceptance/fix-pairs-candidates/pairs.toml`](../../test/acceptance/fix-pairs-candidates/pairs.toml).
It holds exactly the 26 rows of section 3, with `holdout = false` and a description that marks it
unreviewed. `observability.findings.corpus.load_fix_pairs` accepts it.

## 2. Method

Sources, all public and read without authentication:

- **N**: the NVD CVE record, read as JSON from `services.nvd.nist.gov/rest/json/cves/2.0?cveId=<id>` (the
  same record as `nvd.nist.gov/vuln/detail/<id>`): description, weaknesses with their source (the assigning
  CNA or NVD), CVSS and references. Candidates were discovered with the same API's keyword search.
- **C**: the GitHub commit record of the fix, `api.github.com/repos/<owner>/<repo>/commits/<sha>` (the same
  commit as `github.com/<owner>/<repo>/commit/<sha>`): full hash, parent hashes, changed files and the patch.
- **I**: the GitHub issue event list, `api.github.com/repos/<owner>/<repo>/issues/<n>/events`, where the CVE
  record names an issue instead of a commit; the closing event carries the closing commit.
- **L**: the repository record and licence file, `api.github.com/repos/<owner>/<repo>` and `.../license`.

Rules applied:

- A hash is written here only if it was read in one of those records during this session. Every pre-fix
  revision is the single parent of the fixing commit, read from **C**. A script then re-checked the draft
  file against the saved records: fixing hash, parent hash, repository, file path, and that the recorded lines
  fall inside a pre-image hunk of the patch. All 26 pairs passed.
- Line numbers are pre-fix line numbers computed from the patch hunk headers. `line`..`end_line` is the
  removed or guarded code; `scope_start`..`scope_end` is the range of the visible hunks, **not** the
  enclosing function, because no source file was read in full.
- CWE: where the assigning CNA states a CWE, the draft uses it; otherwise NVD's. Both are listed. One
  record has neither and carries a proposal marked PROPOSED.
- Severity in the draft is the CNA's CVSS band where the CNA scored the record, otherwise NVD's.
- Attacker position is a judgement from the advisory text, with the reason given.
- `weakness_class` in the draft is a free-text label chosen here; it is not from any advisory.

## 3. Verified candidates (26)

Verification column: the number is the item (1 advisory, 2 fixing commit, 3 parent commit, 4 file and lines,
5 weakness class, 6 licence) and the letter is the source of section 2.

| Id | Project | Repository | Licence | Advisory | Fixing commit | Parent commit | File | Pre-fix lines | CWE | Attacker position | Description | Verification |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `gns-cve-2020-6016` | ValveSoftware/GameNetworkingSockets | <https://github.com/ValveSoftware/GameNetworkingSockets> | BSD-3-Clause | [CVE-2020-6016](https://nvd.nist.gov/vuln/detail/CVE-2020-6016) | [`e0c86dcb9139771db3db0cfdb1fb8bef0af19c43`](https://github.com/ValveSoftware/GameNetworkingSockets/commit/e0c86dcb9139771db3db0cfdb1fb8bef0af19c43) | `e950c994de831c02972e4d11495ca83146b9714b` | `src/steamnetworkingsockets/clientlib/steamnetworkingsockets_snp.cpp` | 580-584 | CNA (Check Point) CWE-590; NVD CWE-787 | `peer_to_peer`: The library serves client-server and peer-to-peer connections; any connected peer sends the segment. | An unreliable-segment offset and size from the peer reach `SNP_ReceiveUnreliableSegment` without a bound. | 1: N. 2: N (reference names the commit), C. 3-4: C. 5: N. 6: L. |
| `gns-cve-2020-6018` | ValveSoftware/GameNetworkingSockets | <https://github.com/ValveSoftware/GameNetworkingSockets> | BSD-3-Clause | [CVE-2020-6018](https://nvd.nist.gov/vuln/detail/CVE-2020-6018) | [`bea84e2844b647532a9b7fbc3a6a8989d66e49e3`](https://github.com/ValveSoftware/GameNetworkingSockets/commit/bea84e2844b647532a9b7fbc3a6a8989d66e49e3) | `d885e72b436b0f76d73c8926de7368c1a2fad173` | `src/common/crypto_libsodium.cpp` | 75-85 | CNA CWE-120; NVD CWE-787 | `peer_to_peer`: Any connected peer sends the encrypted message that is decrypted into the caller's buffer. | The libsodium `AES_GCM_DecryptContext::Decrypt` wrapper does not check the output buffer size. | 1: N. 2: N (reference names the commit), C. 3-4: C. 5: N. 6: L. |
| `gns-cve-2020-6019` | ValveSoftware/GameNetworkingSockets | <https://github.com/ValveSoftware/GameNetworkingSockets> | BSD-3-Clause | [CVE-2020-6019](https://nvd.nist.gov/vuln/detail/CVE-2020-6019) | [`d944a10808891d202bb1d5e1998de6e0423af678`](https://github.com/ValveSoftware/GameNetworkingSockets/commit/d944a10808891d202bb1d5e1998de6e0423af678) | `e0c86dcb9139771db3db0cfdb1fb8bef0af19c43` | `src/steamnetworkingsockets/clientlib/steamnetworkingsockets_udp.cpp` | 843 | CNA CWE-248; NVD gives none (NVD-CWE-noinfo) | `peer_to_peer`: Any connected peer sends the data packet with an inlined statistics blob. | The stats-blob size check in `Received_Data` uses pointer arithmetic that can overflow. | 1: N. 2: N (reference names the commit), C. 3-4: C. 5: N. 6: L. |
| `teeworlds-cve-2020-12066` | teeworlds/teeworlds | <https://github.com/teeworlds/teeworlds> | Zlib | [CVE-2020-12066](https://nvd.nist.gov/vuln/detail/CVE-2020-12066) | [`c68402fa7e279d42886d5951d1ea8ac2facc1ea5`](https://github.com/teeworlds/teeworlds/commit/c68402fa7e279d42886d5951d1ea8ac2facc1ea5) | `b992b0a5e114ecfb06fb5155029dbc5238614cbe` | `src/engine/server/server.cpp` | 499-500 | NVD CWE-20 | `client_to_server`: The CVE record says remote attackers shut down the server. | `CServer::SendMsg` does not reject an invalid or empty client id. | 1: N. 2: N (reference names the commit), C. 3-4: C. 5: N. 6: L. |
| `teeworlds-cve-2016-9400` | teeworlds/teeworlds | <https://github.com/teeworlds/teeworlds> | Zlib | [CVE-2016-9400](https://nvd.nist.gov/vuln/detail/CVE-2016-9400) | [`ff254722a2683867fcb3e67569ffd36226c4bc62`](https://github.com/teeworlds/teeworlds/commit/ff254722a2683867fcb3e67569ffd36226c4bc62) | `3e1d02283896d4b03e1ab9f9ef20ce4c30c8a0cd` | `src/engine/client/client.cpp` | 1242 | NVD CWE-119 | `server_to_client`: The CVE record names remote servers as the attacker and the client packet handler as the target. | `CClient::ProcessServerPacket` does not bound the snapshot part count, part index and part size. | 1: N. 2: N (reference names the commit), C. 3-4: C. 5: N. 6: L. |
| `teeworlds-cve-2019-10878` | teeworlds/teeworlds | <https://github.com/teeworlds/teeworlds> | Zlib | [CVE-2019-10878](https://nvd.nist.gov/vuln/detail/CVE-2019-10878) | [`e086f4b35b1adf7edc35b4ad332dc7ed1edc5988`](https://github.com/teeworlds/teeworlds/commit/e086f4b35b1adf7edc35b4ad332dc7ed1edc5988) | `d25869626a8cfbdd320929ba93ce73abed1402ce` | `src/engine/shared/datafile.cpp` | 313-329 | NVD CWE-787 | `hostile_content`: The input is a map datafile, which a client also receives from a server it joins. | `CDataFileReader` indexes `m_ppDataPtrs` without checking the index against the raw-data count. | 1: N. 2: N (names the issue), I, C. 3-4: C. 5: N. 6: L. |
| `teeworlds-cve-2019-10879` | teeworlds/teeworlds | <https://github.com/teeworlds/teeworlds> | Zlib | [CVE-2019-10879](https://nvd.nist.gov/vuln/detail/CVE-2019-10879) | [`4d529dcd2d01022e979ebfa0b91167dee37cdb8e`](https://github.com/teeworlds/teeworlds/commit/4d529dcd2d01022e979ebfa0b91167dee37cdb8e) | `40bedbecbd004d13e435d79fb7be3f3d55787d9a` | `src/engine/shared/datafile.cpp` | 131-140 | NVD CWE-190 | `hostile_content`: The input is a map datafile, which a client also receives from a server it joins. | `CDataFileReader::Open` computes allocation sizes from header counts in unsigned 32-bit arithmetic. | 1: N. 2: N (names the issue), I, C. 3-4: C. 5: N. 6: L. |
| `ioq3-cve-2017-11721` | ioquake/ioq3 | <https://github.com/ioquake/ioq3> | GPL-2.0 | [CVE-2017-11721](https://nvd.nist.gov/vuln/detail/CVE-2017-11721) | [`d2b1d124d4055c2fcbe5126863487c52fd58cca1`](https://github.com/ioquake/ioq3/commit/d2b1d124d4055c2fcbe5126863487c52fd58cca1) | `2d6171f44c72177a4b996eb721f353839fb5273d` | `code/qcommon/msg.c` | 179-218 | NVD CWE-119 | `client_to_server`: The record says only 'crafted packet'; `MSG_ReadBits` parses every incoming message on client and server, and a remote client against a server is the stronger position. | `MSG_ReadBits` reads past the end of the message buffer. | 1: N. 2: N (reference names the commit), C. 3-4: C. 5: N. 6: L. |
| `chocolate-doom-cve-2020-14983` | chocolate-doom/chocolate-doom | <https://github.com/chocolate-doom/chocolate-doom> | GPL-2.0 | [CVE-2020-14983](https://nvd.nist.gov/vuln/detail/CVE-2020-14983) | [`f1a8d991aa8a14afcb605cf2f65cd15fda204c56`](https://github.com/chocolate-doom/chocolate-doom/commit/f1a8d991aa8a14afcb605cf2f65cd15fda204c56) | `5bf73c4864fedb6b97b27bf302435a1168ba8f4c` | `src/net_structrw.c` | 119-122 | NVD CWE-120 | `client_to_server`: The CVE record says a malicious user overwrites the server's stack. | `NET_ReadSettings` loops over a packet-supplied `num_players` without bounding it by `NET_MAXPLAYERS`. | 1: N. 2: N (names the issue), I, C. 3-4: C. 5: N. 6: L. |
| `minetest-cve-2022-24300` | luanti-org/luanti | <https://github.com/luanti-org/luanti> | LGPL-2.1-or-later | [CVE-2022-24300](https://nvd.nist.gov/vuln/detail/CVE-2022-24300) | [`b5956bde259faa240a81060ff4e598e25ad52dae`](https://github.com/luanti-org/luanti/commit/b5956bde259faa240a81060ff4e598e25ad52dae) | `ed0882fd58fb0f663cc115d23a11643874facc06` | `src/itemstackmetadata.cpp` | 42-43 | PROPOSED CWE-74; NVD gives none (NVD-CWE-Other) | `client_to_server`: The record says saved user input; a player-supplied string is stored by the server into item metadata. | `ItemStackMetadata::setString` stores strings containing the serialization delimiters unchanged. | 1: N. 2: N (reference names the commit), C. 3-4: C. 5: N. 6: L. |
| `minetest-cve-2022-24301` | luanti-org/luanti | <https://github.com/luanti-org/luanti> | LGPL-2.1-or-later | [CVE-2022-24301](https://nvd.nist.gov/vuln/detail/CVE-2022-24301) | [`3693b6871eba268ecc79b3f52d00d3cefe761131`](https://github.com/luanti-org/luanti/commit/3693b6871eba268ecc79b3f52d00d3cefe761131) | `d28f1b01707dfa15e770096a26495452513bc56f` | `src/network/serverpackethandler.cpp` | 633-639 | NVD CWE-276 | `client_to_server`: A connected player sends the inventory action that the server applies. | `handleCommand_InventoryAction` does not reject actions naming another player's inventory. | 1: N. 2: N (reference names the commit), C. 3-4: C. 5: N. 6: L. |
| `minetest-cve-2022-35978` | luanti-org/luanti | <https://github.com/luanti-org/luanti> | LGPL-2.1-or-later | [CVE-2022-35978](https://nvd.nist.gov/vuln/detail/CVE-2022-35978) | [`da71e86633d0b27cd02d7aac9fdac625d141ca13`](https://github.com/luanti-org/luanti/commit/da71e86633d0b27cd02d7aac9fdac625d141ca13) | `bccaf5fc2d11c31615d64b9bca91f908d06b7044` | `src/script/lua_api/l_settings.cpp` | 41-58 | CNA (GitHub) CWE-693; NVD gives none | `hostile_content`: The attacker is a mod loaded in single player. | `checkSettingSecurity` lets a mod set `main_menu_script`, which is later run unsandboxed. | 1: N. 2: N (reference names the commit), C. 3-4: C. 5: N. 6: L. |
| `luanti-cve-2026-41196` | luanti-org/luanti | <https://github.com/luanti-org/luanti> | LGPL-2.1-or-later | [CVE-2026-41196](https://nvd.nist.gov/vuln/detail/CVE-2026-41196) | [`8a929dfb97aa08337f49ba1bb96a56d6557dc896`](https://github.com/luanti-org/luanti/commit/8a929dfb97aa08337f49ba1bb96a56d6557dc896) | `b3de90634a3061b9612eecf2067b3e3d2075db3a` | `src/script/cpp_api/s_security.cpp` | 28-49 | CNA (GitHub) CWE-94 | `hostile_content`: The attacker is a mod running in the Lua sandbox. | Whitelisted functions are copied into the sandbox with their original environment, allowing escape. | 1: N. 2: N (reference names the commit), C. 3-4: C. 5: N. 6: L. |
| `godot-cve-2021-26826` | godotengine/godot | <https://github.com/godotengine/godot> | MIT | [CVE-2021-26826](https://nvd.nist.gov/vuln/detail/CVE-2021-26826) | [`403e4fd08b0b212e96f53d926e6273e0745eaa5a`](https://github.com/godotengine/godot/commit/403e4fd08b0b212e96f53d926e6273e0745eaa5a) | `1d1310f3d7fbde091771ee7bb98bb94e60432696` | `modules/tga/image_loader_tga.cpp` | 133-175 | NVD CWE-787 | `hostile_content`: The input is a TGA image file loaded as an asset. | The TGA loader reads and writes pixel buffers without checking them against the decoded size. | 1: N. 2: N (reference names the commit), C. 3-4: C. 5: N. 6: L. |
| `sdl-cve-2021-33657` | libsdl-org/SDL | <https://github.com/libsdl-org/SDL> | Zlib | [CVE-2021-33657](https://nvd.nist.gov/vuln/detail/CVE-2021-33657) | [`8c91cf7dba5193f5ce12d06db1336515851c9ee9`](https://github.com/libsdl-org/SDL/commit/8c91cf7dba5193f5ce12d06db1336515851c9ee9) | `056c09942dbffaa128612fc6f1969ab0fc28e2ac` | `src/video/SDL_pixels.c` | 950 | NVD CWE-787 | `hostile_content`: The input is a BMP image file. | Palette maps are allocated for `ncolors` entries but indexed by pixel values up to 255. | 1: N. 2: N (reference names the commit), C. 3-4: C. 5: N. 6: L. |
| `rathena-cve-2025-58447` | rathena/rathena | <https://github.com/rathena/rathena> | GPL-3.0 | [CVE-2025-58447](https://nvd.nist.gov/vuln/detail/CVE-2025-58447) | [`2f5248b9cd9a8c6b42422ddecfc4cc2cd0e69e4b`](https://github.com/rathena/rathena/commit/2f5248b9cd9a8c6b42422ddecfc4cc2cd0e69e4b) | `6f23443ab8169afe7295a8375f7532af45947912` | `src/login/loginclif.cpp` | 343 | CNA (GitHub) CWE-122; NVD CWE-787 | `client_to_server`: The record says a remote attacker sends a crafted login request to the login server. | The SSO login handler copies the token using the packet's token length, not the destination size. | 1: N. 2: N (reference names the commit), C. 3-4: C. 5: N. 6: L. |
| `rathena-cve-2025-58448` | rathena/rathena | <https://github.com/rathena/rathena> | GPL-3.0 | [CVE-2025-58448](https://nvd.nist.gov/vuln/detail/CVE-2025-58448) | [`0d89ae071ff5e46e8dedcf45d060acec84b3abb5`](https://github.com/rathena/rathena/commit/0d89ae071ff5e46e8dedcf45d060acec84b3abb5) | `2f5248b9cd9a8c6b42422ddecfc4cc2cd0e69e4b` | `src/web/partybooking_controller.cpp` | 259 | CNA (GitHub) CWE-89 | `client_to_server`: A remote client sends the `WorldName` parameter to the web server's party-booking handler. | `partybooking_delete` formats an unescaped request value into a SQL statement. | 1: N. 2: N (reference names the commit), C. 3-4: C. 5: N. 6: L. |
| `rathena-cve-2025-58750` | rathena/rathena | <https://github.com/rathena/rathena> | GPL-3.0 | [CVE-2025-58750](https://nvd.nist.gov/vuln/detail/CVE-2025-58750) | [`0cc348b186bbcc3c604c17c39589a319f27d469b`](https://github.com/rathena/rathena/commit/0cc348b186bbcc3c604c17c39589a319f27d469b) | `0d89ae071ff5e46e8dedcf45d060acec84b3abb5` | `src/char/char_clif.cpp` | 79-87 | CNA (GitHub) CWE-119, CWE-125, CWE-787; NVD CWE-125, CWE-787 | `client_to_server`: A connected client sends the character-slot move request. | `chclif_parse_moveCharSlot` indexes per-session arrays with client-supplied slot numbers. | 1: N. 2: N (reference names the commit), C. 3-4: C. 5: N. 6: L. |
| `rathena-cve-2025-62170` | rathena/rathena | <https://github.com/rathena/rathena> | GPL-3.0 | [CVE-2025-62170](https://nvd.nist.gov/vuln/detail/CVE-2025-62170) | [`af2f3ba33fc03dc6dd510f8cfe84cd9185af748d`](https://github.com/rathena/rathena/commit/af2f3ba33fc03dc6dd510f8cfe84cd9185af748d) | `6b5c231ff08faa4027bb3b1806295b889c5ae9e0` | `src/map/clif.cpp` | 16718 | CNA (GitHub) CWE-416 | `client_to_server`: The record says an unauthenticated attacker crashes the map server through RODEX mail. | `clif_mail_removeitem` dereferences `inventory_data` through a stored mail item index without a check. | 1: N. 2: N (reference names the commit), C. 3-4: C. 5: N. 6: L. |
| `freeciv21-cve-2026-33250` | longturn/freeciv21 | <https://github.com/longturn/freeciv21> | GPL-3.0 | [CVE-2026-33250](https://nvd.nist.gov/vuln/detail/CVE-2026-33250) | [`ad8e18ca22595529599782b2984bf44df8d69ed6`](https://github.com/longturn/freeciv21/commit/ad8e18ca22595529599782b2984bf44df8d69ed6) | `2b1aedc1c7b4607ae2e646b51379d94b1d8fe4bc` | `common/networking/packets.cpp` | 464 | CNA (GitHub) CWE-20, CWE-121 | `client_to_server`: The record leads with a remote attacker taking down a public server; it also says a malicious server can crash a client. | A compressed packet is decompressed and then processed by a recursive call, with no depth limit. | 1: N. 2: N (reference names the commit), C. 3-4: C. 5: N. 6: L. |
| `freeciv-cve-2026-90556` | freeciv/freeciv | <https://github.com/freeciv/freeciv> | GPL-2.0 | [CVE-2026-90556](https://nvd.nist.gov/vuln/detail/CVE-2026-90556) | [`75ecde3e86ddf2fe775768450e9a290a4f4d4387`](https://github.com/freeciv/freeciv/commit/75ecde3e86ddf2fe775768450e9a290a4f4d4387) | `b1b0768bfaca9b2fae68f9466defe1e80636e9fa` | `server/savegame/savegame3.c` | 980-983 | CNA (VulnCheck) CWE-122 | `hostile_content`: The input is a savegame file. | `worklist_load` uses a savegame-supplied worklist length as a loop bound over a fixed array. | 1: N. 2: N (reference names the commit), C. 3-4: C. 5: N. 6: L. |
| `freeciv-cve-2026-90557` | freeciv/freeciv | <https://github.com/freeciv/freeciv> | GPL-2.0 | [CVE-2026-90557](https://nvd.nist.gov/vuln/detail/CVE-2026-90557) | [`ef0c76c2765fe383140eb1a70dbea1228844152e`](https://github.com/freeciv/freeciv/commit/ef0c76c2765fe383140eb1a70dbea1228844152e) | `75ecde3e86ddf2fe775768450e9a290a4f4d4387` | `server/savegame/savegame3.c` | 6121-6122 | CNA (VulnCheck) CWE-125 | `hostile_content`: The input is a savegame file. | `sg_load_player_unit` indexes `activities.order` with a savegame-supplied index. | 1: N. 2: N (reference names the commit), C. 3-4: C. 5: N. 6: L. |
| `assimp-cve-2026-117608` | assimp/assimp | <https://github.com/assimp/assimp> | BSD-3-Clause | [CVE-2026-117608](https://nvd.nist.gov/vuln/detail/CVE-2026-117608) | [`7dbc85d9218fae017d4fad70269e7569f7b0c870`](https://github.com/assimp/assimp/commit/7dbc85d9218fae017d4fad70269e7569f7b0c870) | `1edd666bbe6370e316716d1b2b74e04a24901493` | `code/AssetLib/MD2/MD2Loader.cpp` | 174-180 | CNA (VulnCheck) CWE-190 | `hostile_content`: The input is an MD2 model file. | `MD2Importer::ValidateHeader` computes the frame-table bound in 32-bit arithmetic that can wrap. | 1: N. 2: N (reference names the commit), C. 3-4: C. 5: N. 6: L. |
| `tinygltf-cve-2022-3008` | syoyo/tinygltf | <https://github.com/syoyo/tinygltf> | MIT | [CVE-2022-3008](https://nvd.nist.gov/vuln/detail/CVE-2022-3008) | [`52ff00a38447f06a17eab1caa2cf0730a119c751`](https://github.com/syoyo/tinygltf/commit/52ff00a38447f06a17eab1caa2cf0730a119c751) | `544969b7324cd6bba29f6203c7d78c7ea92dbab0` | `tiny_gltf.h` | 2607-2655 | CNA (Google) CWE-78; NVD CWE-77 | `hostile_content`: The input is a glTF asset whose embedded paths are expanded. | `ExpandFilePath` passes paths from the input file to `wordexp`, which performs command substitution. | 1: N. 2: N (reference names the commit), C. 3-4: C. 5: N. 6: L. |
| `akashi-cve-2022-31135` | AttorneyOnline/akashi | <https://github.com/AttorneyOnline/akashi> | AGPL-3.0 | [CVE-2022-31135](https://nvd.nist.gov/vuln/detail/CVE-2022-31135) | [`5566cdfedddef1f219aee33477d9c9690bf2f78b`](https://github.com/AttorneyOnline/akashi/commit/5566cdfedddef1f219aee33477d9c9690bf2f78b) | `78f3e1d3d175c94c14734b3b2d0a3f1167eec2f7` | `core/src/packets.cpp` | 381 | CNA (GitHub) and NVD CWE-129 | `client_to_server`: A connected client sends the evidence packet. | The evidence edit and remove handlers accept an index equal to the list size. | 1: N. 2: N (reference names the commit), C. 3-4: C. 5: N. 6: L. |
| `moonlight-cve-2023-42801` | moonlight-stream/moonlight-common-c | <https://github.com/moonlight-stream/moonlight-common-c> | GPL-3.0 | [CVE-2023-42801](https://nvd.nist.gov/vuln/detail/CVE-2023-42801) | [`b2497a3918a6d79808d9fd0c04734786e70d5954`](https://github.com/moonlight-stream/moonlight-common-c/commit/b2497a3918a6d79808d9fd0c04734786e70d5954) | `8b84d17c8d34e76d2531c6695d61349776474df2` | `src/Misc.c` | 83-108 | CNA (GitHub) CWE-120 | `server_to_client`: The record names a malicious game streaming server attacking the client. | `extractVersionQuadFromString` copies a host-supplied version string into a 128-byte stack buffer. | 1: N. 2: N (reference names the commit), C. 3-4: C. 5: N. 6: L. |

Spread: `client_to_server` 11, `hostile_content` 10, `peer_to_peer` 3, `server_to_client` 2, `local` 0.
No candidate with a `local` attacker position was found that met all six items.

### Notes a reviewer needs for individual rows

- **GameNetworkingSockets.** CVE-2020-6016 and CVE-2020-6017 reference the same fixing commit; only
  CVE-2020-6016 is listed. For all three rows the CNA's CWE (CWE-590, CWE-120, CWE-248) describes the
  consequence the reporter observed, while the fix is a missing bound or an overflowing check; NVD's CWE-787
  may score better for the first two. CVE-2020-6018 applies only to builds that use libsodium.
- **Teeworlds CVE-2019-10878 and CVE-2019-10879.** The CVE records name issues 2073 and 2070, not commits.
  The fixing commits were read from the issues' closing events, and both commit messages name the issue.
- **Chocolate Doom CVE-2020-14983.** The CVE record names issue 1293; the closing commit's message names the
  CVE. The record also covers Crispy Doom, which is not listed.
- **ioquake3 CVE-2017-11721.** The fix also changes `code/qcommon/huffman.c` and `MSG_WriteBits`; the listed
  lines are the read path in `MSG_ReadBits` only.
- **Minetest and Luanti.** `minetest/minetest` now redirects to `luanti-org/luanti`; the hashes are
  unchanged. CVE-2022-24301 carries NVD's CWE-276, although the defect is a missing ownership check on a
  client request (CWE-639 or CWE-862 would describe it more closely). CVE-2022-24300 has no stated CWE;
  CWE-74 is proposed because delimiter characters in user input are not neutralized before serialization
  (CWE-140 is the narrower child). CVE-2026-41196 is fixed by a 105-line rewrite across
  `initializeSecurity`; the listed lines are the two copy helpers and the scope is the whole changed range,
  so this row needs the closest reading. CVE-2026-40959 references the same commit and one more.
- **Godot CVE-2021-26826.** The listed commit is the pull-request commit on `master`; the pull request
  record reports it merged. CVE-2021-26825 points at pull request 45702, whose single commit has the same
  title on another branch, so the two CVEs appear to share one fix; only one is listed. The line NVD quotes
  for CVE-2021-26825 (`buffer_size` computation) is pre-fix line 282 of the same file.
- **SDL CVE-2021-33657.** Two allocation sites are fixed: pre-fix lines 950 (`Map1to1`) and 974 (`Map1toN`).
  The scope covers both. SDL is a library used by games, not a game.
- **rAthena.** CVE-2025-62170 is described as a use-after-free, but the fix adds an index range check and a
  null check; the stated CWE-416 is kept. CVE-2025-58448 is in the optional web server component.
- **Freeciv21 CVE-2026-33250.** The fix rewrites the whole packet reader (125 additions, 95 deletions). The
  listed line is the removed recursive call; the scope starts at the removed function header.
- **Freeciv CVE-2026-90556 and CVE-2026-90557.** Each fix changes `savegame2.c` and `savegame3.c` the same
  way; `savegame3.c` is listed (the `savegame2.c` sites are pre-fix lines 804-807 and 4294-4295). The CVE
  records cite line numbers at tag `R3_2_5`, which differ from the parent commit's, so the fixing commits
  are probably on the development branch and the release branch carries separate backports.
  `test/acceptance/freeciv-instrumented` already exists in this repository; check whether Freeciv pairs
  overlap with a target already used for tuning.
- **tinygltf CVE-2022-3008.** The patch shows the first and last lines of `ExpandFilePath` only; the
  `wordexp` call itself lies between them and was not read.
- **Akashi CVE-2022-31135.** Two handlers are fixed (pre-fix lines 381 and 394); the scope covers both.
- **Moonlight CVE-2023-42801.** A game-streaming client library, the only non-Teeworlds
  `server_to_client` row. Whether streaming clients are in scope is the owner's call.

## 4. Unverified leads

Not in the draft file. Hashes below were read in an NVD reference or a GitHub record but the commit itself
was not opened unless stated.

| Advisory | Project | What was read | What is missing |
| --- | --- | --- | --- |
| CVE-2019-10877 | teeworlds/teeworlds | NVD (CWE-190, `CMap::Load` integer overflow) names issue 2071. The issue has no closing commit; its events reference `d25869626a8cfbdd320929ba93ce73abed1402ce`, which is also the parent of the CVE-2019-10878 fix. | The referenced commit was not opened, so the fix, its parent and the lines are unconfirmed. |
| CVE-2021-43518 | teeworlds/teeworlds | NVD (CWE-120, map `m_Channels` not validated, server-supplied map) names issue 2981. | The issue was closed with no commit event; fixing commit unknown. |
| CVE-2018-18541 | teeworlds/teeworlds | NVD (CWE-20, connection packets forgeable) names issue 1536. | No commit reference. |
| CVE-2019-10069 | godotengine/godot | NVD (CWE-502, deserialization policy not applied to multiplayer RPC arguments) names pull request 27398. Its commit `65c7fd209947d5b2e080c9818b5a0df7c7d02440` (parent `81292665d5dcc991d3c9341245b269193329ee22`) changes `core/io/multiplayer_api.cpp` lines 302 and 338. | The pull request record reports `merged: false`, so whether this exact commit is in upstream history is unconfirmed. It is the only lead for an unvalidated replication RPC (T-070). |
| CVE-2021-26825 | godotengine/godot | Pull request 45702, commit `113b5ab1c45c01b8e6d54d13ac8876d091f883a8`. | Appears to be the same fix as CVE-2021-26826 on another branch; commit not opened. |
| CVE-2020-6017 | ValveSoftware/GameNetworkingSockets | Same fixing commit as CVE-2020-6016. | Not a separate location; listing both would double-count. |
| CVE-2017-6903 | ioquake/ioq3 | NVD (no CWE; auto-downloaded files loaded as native code) references three ioq3 commits, among them `376267d534476a875d8b9228149c4ee18b74a4fd`. | Three commits, none opened; no single defect location. |
| CVE-2023-42799, CVE-2023-42800 | moonlight-stream/moonlight-common-c | NVD (CWE-120) references `02b7742f4d19631024bd766bd2bb76715780004e` and `24750d4b748fefa03d09fcfd6d45056faca354e0`. | Commits not opened. |
| CVE-2026-40959, CVE-2026-40960 | luanti-org/luanti | NVD (CWE-829, CWE-670; Lua sandbox escapes) references further commits, among them `53cef183e2a85a4daff84ac1a9a7946f940da8f8` and `0faf529bc4b89e70a275ed1162047815118f2413`. | Commits not opened. |
| CVE-2025-2592, CVE-2025-3015 and other Assimp records | assimp/assimp | NVD keyword search returned 75 Assimp records; several reference commits, for example `2690e354da0c681db000cfd892a55226788f2743`. | Only CVE-2026-117608 was opened. More asset-parser pairs are available if wanted. |
| CVE-2025-15533, CVE-2025-15534 | raysan5/raylib | NVD (heap overflow and integer overflow in font loading) references `5a3391fdce046bc5473e52afbd835dd2dc127146`. | Commit and licence not read. |
| CVE-2022-39047 | Freeciv | NVD (CWE-120, modpack installer URL handling) references two oss-security posts. | No commit reference. |
| CVE-2018-1999023 | Battle for Wesnoth | NVD (CWE-94, Lua sandbox escape via saved games and network games) references a gist. | No commit reference. |
| CVE-2019-20797 | prboom-plus | NVD (CWE-787, UDP packet handling) references two SourceForge bug pages. | No commit reference; repository not on the pages read. |
| CVE-2025-54065 | ZDoom/gzdoom | NVD (CWE-913, ZScript state handling) references a GitHub advisory. | No commit reference. |
| CVE-2020-15007 | id Tech 1 (`M_LoadDefaults`) | NVD (CWE-120, config file parsing; the only `local`-style lead) references a commit in `AXDOOMER/doom-vanille`. | That repository is one fork, not an upstream; not opened. |
| OpenTTD | OpenTTD | NVD keyword search returned 20 records. | None carried a commit, pull-request or advisory reference in the form searched for. |

## 5. Where sources disagreed

- CNA and NVD assign different CWEs for CVE-2020-6016, CVE-2020-6018, CVE-2020-6019, CVE-2025-58447,
  CVE-2025-58750 and CVE-2022-3008 (see the CWE column).
- NVD's severity is higher than the CNA's for CVE-2022-35978 (10.0 against 7.7), CVE-2025-58750 (9.1 against
  8.2), CVE-2025-58448 (9.8 against 9.1) and CVE-2022-31135 (7.5 against 6.5). The draft uses the CNA's band.
- CVE-2025-62170: the description says use-after-free, the fix is a range and null check.
- CVE-2021-26825 and CVE-2021-26826 describe two defects but point at the same fix on two branches.
- CVE-2026-90556 and CVE-2026-90557 cite release-tag line numbers that differ from the fixing commit's parent.
- GitHub reports no SPDX id for three repositories whose licence files were then read (section 7).

## 6. What a reviewer must still do

1. Choose which projects are acceptable targets at all (size, build cost, licence).
2. Clone each chosen project and confirm that both revisions exist on an upstream branch and that the
   pre-fix revision is the direct parent of the fix. For Godot, Teeworlds and Freeciv in particular, confirm
   the commit is on the branch you intend to build.
3. Confirm that each pair builds at both revisions with the tracing the review needs. Old revisions
   (Teeworlds 2016, ioquake3 2017, Godot 2021) may need old toolchains.
4. Open the pre-fix file and confirm `line`..`end_line`; replace `scope_start`..`scope_end` with the
   enclosing function. The scopes here are hunk ranges and are too narrow or, for Luanti CVE-2026-41196 and
   Freeciv21, too wide.
5. Decide the CWE where CNA and NVD differ, and the one PROPOSED value.
6. Decide the attacker position where the shared code runs on both sides (ioquake3, Freeciv21).
7. Decide which pairs form the public corpus and which the private holdout. A holdout drawn from widely
   discussed CVEs may be known to a model; the 2026 records are the least exposed. Record holdout use in the
   ledger.
8. Acquire and pin the targets, write the keys outside the targets with `write_scoring_key` (one key per
   project and revision; the two Teeworlds datafile pairs and the two Freeciv pairs share a path), and
   rename or replace the draft file. T-067 is done only when at least ten pairs are keyed this way.

## 7. Licence notes

Licences are as GitHub reports them for the default branch today, not as checked at the listed revisions.

| Project | Licence | Source |
| --- | --- | --- |
| ValveSoftware/GameNetworkingSockets | BSD-3-Clause | GitHub SPDX id |
| teeworlds/teeworlds | Zlib | GitHub reports no SPDX id. `license.txt` was read: the zlib licence text for the source, CC-BY-SA 3.0 for `data` and `datasrc`, and a note that `src/engine/external` holds libraries under their own licences. |
| ioquake/ioq3 | GPL-2.0 | GitHub SPDX id |
| chocolate-doom/chocolate-doom | GPL-2.0 | GitHub SPDX id |
| luanti-org/luanti | LGPL-2.1-or-later | GitHub reports no SPDX id. `LICENSE.txt` was read: source code under LGPL 2.1 or later; media under CC BY-SA and others. |
| godotengine/godot | MIT | GitHub SPDX id |
| libsdl-org/SDL | Zlib | GitHub SPDX id |
| rathena/rathena | GPL-3.0 | GitHub SPDX id |
| longturn/freeciv21 | GPL-3.0 | GitHub SPDX id |
| freeciv/freeciv | GPL-2.0 | GitHub SPDX id |
| assimp/assimp | BSD-3-Clause | GitHub reports no SPDX id. `LICENSE` was read: a three-clause BSD text, with an exception for `test/models-nonbsd` and third-party notices. |
| syoyo/tinygltf | MIT | GitHub SPDX id |
| AttorneyOnline/akashi | AGPL-3.0 | GitHub SPDX id |
| moonlight-stream/moonlight-common-c | GPL-3.0 | GitHub SPDX id |

GitHub's `GPL-2.0`, `GPL-3.0` and `AGPL-3.0` do not say "only" or "or later"; read the file headers before
relying on either. Every licence here permits cloning and analysing the source. The corpus file holds only
identifiers, paths and line numbers, no project source.
