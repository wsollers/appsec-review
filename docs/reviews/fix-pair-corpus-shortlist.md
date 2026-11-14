---
title: "T-067: ten game and engine CVE fix-pair candidates"
kind: "review"
subsystem: "testing and operations"
status: "historical"
jobs: []
last reconciled: "16201c1537bc7559aafcf86c17d02d8fb8fa291e"
---
# T-067: ten game and engine CVE fix-pair candidates

Research-only survey for **T-067**, checked against public upstream records on **2026-11-12**. This shortlist contains **10 distinct CVEs and fixing commits across 7 projects**. It builds on the existing 26-row inventory in `docs/reviews/fix-pair-corpus-candidates.md`; it does not replace that inventory or modify `test/acceptance/fix-pairs-candidates/pairs.toml`.

Updated the same day with repository/release sizes, a small-first recommendation, and separate Unity/Unreal research leads. Those supplemental leads do not increase the count of ten qualifying open-source candidates.

**These are candidates, not admitted or validated corpus cases.** No target tree was acquired, cloned, built, executed, or pinned. No scoring key, negative-control label, holdout assignment, or loader change was made. T-067 remains in progress.

## Start small: project and release sizes

**Start with Akashi, then Chocolate Doom.** Akashi has the smallest reported repository of the seven and a two-site index-boundary fix. Chocolate Doom is also small and provides a narrow C network-parser case. GameNetworkingSockets is similarly small, but its crypto/backend requirements make CVE-2020-6018 a less straightforward first case. This is a research recommendation, not a measured build-time ranking.

Sizes below were obtained **without downloading packages or target trees** on 2026-11-12. **GB means decimal GB: 1,000,000,000 bytes.** Repository estimates use GitHub's reported `size` field, interpreting its kilobytes as 1,024 bytes: `size * 1024 / 1e9`. The raw API value is retained so the conversion is explicit. Release sizes use the asset's exact byte count divided by `1e9`.

| Project, smallest repository first | API `size` (KB) | Approx. repository GB | Example published release download | Size caveat |
| --- | ---: | ---: | --- | --- |
| [Akashi](https://api.github.com/repos/AttorneyOnline/akashi) | 7,025 | **0.007194** | [Stable 1.8.1](https://github.com/AttorneyOnline/akashi/releases/tag/1.8.1): `akashi-linux.zip` **0.000903 GB** (902,677 bytes); Windows **0.033448 GB** (33,447,626 bytes) | Smallest source candidate. Verify Qt/runtime dependencies separately; a tiny Linux ZIP is not evidence of a self-contained install. The newer v1.9.0 release is marked prerelease and was not used here. |
| [GameNetworkingSockets](https://api.github.com/repos/ValveSoftware/GameNetworkingSockets) | 17,941 | **0.018372** | [v1.6.1](https://github.com/ValveSoftware/GameNetworkingSockets/releases/tag/v1.6.1): no uploaded assets with a size | GitHub's generated source archives have no asset-byte size in this response; unavailable, not zero. Crypto and other build dependencies are additional. |
| [Chocolate Doom](https://api.github.com/repos/chocolate-doom/chocolate-doom) | 18,441 | **0.018884** | [3.1.1](https://github.com/chocolate-doom/chocolate-doom/releases/tag/chocolate-doom-3.1.1): `chocolate-doom-3.1.1-win64.zip` **0.009799 GB** (9,798,661 bytes) | Good small C candidate. Separate WAD game data and build dependencies are not included in the repository estimate. |
| [ioquake3](https://api.github.com/repos/ioquake/ioq3) | 96,233 | **0.098543** | No published GitHub releases returned | This does not mean that no downloads exist elsewhere. Quake III game data is separate. |
| [Teeworlds](https://api.github.com/repos/teeworlds/teeworlds) | 111,074 | **0.113740** | [0.7.5](https://github.com/teeworlds/teeworlds/releases/tag/0.7.5): source TAR.GZ **0.008936 GB** (8,935,505 bytes); Linux x86-64 TAR.GZ **0.008993 GB** (8,992,685 bytes) | A source snapshot is much smaller than the repository-history estimate. This release is not either exact CVE pair. |
| [Luanti / Minetest](https://api.github.com/repos/luanti-org/luanti) | 143,986 | **0.147442** | [5.18.0](https://github.com/luanti-org/luanti/releases/tag/5.18.0): Windows x64 ZIP **0.017634 GB** (17,634,089 bytes) | Games/mods, dependency builds, and historical Minetest revisions need separate budgeting. |
| [rAthena](https://api.github.com/repos/rathena/rathena) | 411,735 | **0.421617** | No published GitHub releases returned | Largest of these seven; optional web component, database, and game-client requirements add setup cost. |

**These are not historical checkout sizes or total disk budgets.** Repository metadata describes current Git storage, not an exact clone transfer, unpacked source tree, or one selected commit. It does not establish the size of Git LFS payloads, submodule contents, engine/SDK installs, assets, build output, caches, or databases. Release downloads are compressed packages and are shown as examples, not substitutes for the exact pre/post commits. Do not sum all platform assets or infer that a 0.007 GB repository needs only 0.007 GB to build.

## Shortlist

Each pre-fix revision below is the **single direct parent** returned by GitHub's commit API for the listed fix. Links contain the full commit identities; abbreviated display text is only for readability. The licence column describes source code at those historical revisions, not today's default branch and not every bundled asset or dependency.

| # | Project / role | Published CVE | Pre-fix -> fixing commit | Source licence | Candidate coverage |
| --- | --- | --- | --- | --- | --- |
| 1 | Chocolate Doom / game engine | [CVE-2020-14983](https://nvd.nist.gov/vuln/detail/CVE-2020-14983) | [`5bf73c4864fe`](https://github.com/chocolate-doom/chocolate-doom/commit/5bf73c4864fedb6b97b27bf302435a1168ba8f4c) -> [`f1a8d991aa8a`](https://github.com/chocolate-doom/chocolate-doom/commit/f1a8d991aa8a14afcb605cf2f65cd15fda204c56) | GPL-2.0-or-later | Client-to-server player-count bounds |
| 2 | Minetest, now Luanti / voxel engine | [CVE-2022-24301](https://nvd.nist.gov/vuln/detail/CVE-2022-24301) | [`d28f1b01707d`](https://github.com/luanti-org/luanti/commit/d28f1b01707dfa15e770096a26495452513bc56f) -> [`3693b6871eba`](https://github.com/luanti-org/luanti/commit/3693b6871eba268ecc79b3f52d00d3cefe761131) | LGPL-2.1-or-later | Player inventory ownership |
| 3 | Akashi / Attorney Online game server | [CVE-2022-31135](https://nvd.nist.gov/vuln/detail/CVE-2022-31135) | [`78f3e1d3d175`](https://github.com/AttorneyOnline/akashi/commit/78f3e1d3d175c94c14734b3b2d0a3f1167eec2f7) -> [`5566cdfeddde`](https://github.com/AttorneyOnline/akashi/commit/5566cdfedddef1f219aee33477d9c9690bf2f78b) | AGPL-3.0-or-later | Client-to-server index boundary / denial of service |
| 4 | Teeworlds / multiplayer game | [CVE-2016-9400](https://nvd.nist.gov/vuln/detail/CVE-2016-9400) | [`3e1d02283896`](https://github.com/teeworlds/teeworlds/commit/3e1d02283896d4b03e1ab9f9ef20ce4c30c8a0cd) -> [`ff254722a268`](https://github.com/teeworlds/teeworlds/commit/ff254722a2683867fcb3e67569ffd36226c4bc62) | Zlib | Server-to-client snapshot reassembly |
| 5 | GameNetworkingSockets / game networking | [CVE-2020-6016](https://nvd.nist.gov/vuln/detail/CVE-2020-6016) | [`e950c994de83`](https://github.com/ValveSoftware/GameNetworkingSockets/commit/e950c994de831c02972e4d11495ca83146b9714b) -> [`e0c86dcb9139`](https://github.com/ValveSoftware/GameNetworkingSockets/commit/e0c86dcb9139771db3db0cfdb1fb8bef0af19c43) | BSD-3-Clause | Peer-controlled unreliable segment offset/size |
| 6 | GameNetworkingSockets / game networking | [CVE-2020-6018](https://nvd.nist.gov/vuln/detail/CVE-2020-6018) | [`d885e72b436b`](https://github.com/ValveSoftware/GameNetworkingSockets/commit/d885e72b436b0f76d73c8926de7368c1a2fad173) -> [`bea84e2844b6`](https://github.com/ValveSoftware/GameNetworkingSockets/commit/bea84e2844b647532a9b7fbc3a6a8989d66e49e3) | BSD-3-Clause | Decryption output-buffer capacity |
| 7 | Minetest, now Luanti / voxel engine | [CVE-2022-35978](https://nvd.nist.gov/vuln/detail/CVE-2022-35978) | [`bccaf5fc2d11`](https://github.com/luanti-org/luanti/commit/bccaf5fc2d11c31615d64b9bca91f908d06b7044) -> [`da71e86633d0`](https://github.com/luanti-org/luanti/commit/da71e86633d0b27cd02d7aac9fdac625d141ca13) | LGPL-2.1-or-later | Hostile mod / single-player Lua sandbox boundary |
| 8 | ioquake3 / game engine | [CVE-2017-11721](https://nvd.nist.gov/vuln/detail/CVE-2017-11721) | [`2d6171f44c72`](https://github.com/ioquake/ioq3/commit/2d6171f44c72177a4b996eb721f353839fb5273d) -> [`d2b1d124d405`](https://github.com/ioquake/ioq3/commit/d2b1d124d4055c2fcbe5126863487c52fd58cca1) | GPL-2.0-or-later | Network bitstream / Huffman bounds |
| 9 | Teeworlds / multiplayer game | [CVE-2019-10879](https://nvd.nist.gov/vuln/detail/CVE-2019-10879) | [`40bedbecbd00`](https://github.com/teeworlds/teeworlds/commit/40bedbecbd004d13e435d79fb7be3f3d55787d9a) -> [`4d529dcd2d01`](https://github.com/teeworlds/teeworlds/commit/4d529dcd2d01022e979ebfa0b91167dee37cdb8e) | Zlib | Hostile map data / allocation arithmetic |
| 10 | rAthena / MMORPG server | [CVE-2025-58448](https://nvd.nist.gov/vuln/detail/CVE-2025-58448) | [`2f5248b9cd9a`](https://github.com/rathena/rathena/commit/2f5248b9cd9a8c6b42422ddecfc4cc2cd0e69e4b) -> [`0d89ae071ff5`](https://github.com/rathena/rathena/commit/0d89ae071ff5e46e8dedcf45d060acec84b3abb5) | GNU GPL v3; later-version option unresolved | Party-booking web component / SQL injection |

The two GameNetworkingSockets entries are explicitly game-networking library cases, not standalone games. The shortlist covers memory safety, arithmetic, authorization, sandboxing, and SQL handling; it is not a balanced or representative benchmark.

## Evidence and case-specific cautions

### 1. Chocolate Doom: CVE-2020-14983

[Pre-fix source, `src/net_structrw.c:111-125`](https://github.com/chocolate-doom/chocolate-doom/blob/5bf73c4864fedb6b97b27bf302435a1168ba8f4c/src/net_structrw.c#L111-L125) reads a packet-controlled player count and uses it to index `player_classes`. The patch bounds the loop by `NET_MAXPLAYERS`. Its commit message explicitly names the CVE and the [NVD-linked report, chocolate-doom/chocolate-doom#1293](https://github.com/chocolate-doom/chocolate-doom/issues/1293).

NVD identifies Chocolate Doom 3.0.0 and Crispy Doom 5.8.0 as affected. Count this once, not again for Crispy Doom's corresponding change. This is a particularly small candidate diff; valid-player behavior and the precise control scope still need admission-time validation.

### 2. Minetest: CVE-2022-24301

[Pre-fix source, `src/network/serverpackethandler.cpp:623-642`](https://github.com/luanti-org/luanti/blob/d28f1b01707dfa15e770096a26495452513bc56f/src/network/serverpackethandler.cpp#L623-L642) classifies inventory ownership without rejecting another player's named inventory. The patch returns when either player inventory belongs to someone else.

The [maintainer advisory](https://github.com/luanti-org/luanti/security/advisories/GHSA-fvwv-qcq6-wmp5) names the exact fix and 5.4.0 as patched. Its privilege model is a connected player, not an assumed unauthenticated Internet attacker. NVD labels this CWE-276; that label should not silently replace the actual ownership-check behavior when a future key is designed.

### 3. Akashi: CVE-2022-31135

[Pre-fix source, `core/src/packets.cpp:375-395`](https://github.com/AttorneyOnline/akashi/blob/78f3e1d3d175c94c14734b3b2d0a3f1167eec2f7/core/src/packets.cpp#L375-L395) accepts an evidence index equal to the collection size. The patch changes `<=` to `<` in both remove and edit handlers. Treat both sites as one CVE case, not two pairs.

NVD references the exact fix. The [maintainer advisory](https://github.com/AttorneyOnline/akashi/security/advisories/GHSA-vj86-vfmg-q68v) still says patched but not released, whereas NVD describes versions below 1.4 as affected. Use the commit identity, not an inferred release boundary. Both handlers have an evidence-access gate; privilege assumptions need that context.

### 4. Teeworlds: CVE-2016-9400

[Pre-fix source, `src/engine/client/client.cpp:1228-1255`](https://github.com/teeworlds/teeworlds/blob/3e1d02283896d4b03e1ab9f9ef20ce4c30c8a0cd/src/engine/client/client.cpp#L1228-L1255) consumes server-supplied snapshot part metadata before copying into the reassembly buffer. The patch checks part count, part index, and part size, and adds `CSnapshot::MAX_PARTS`.

NVD directly references the fix and identifies releases before 0.6.4. This provides the shortlist's clearest hostile-server-to-client case. Historical build compatibility has not been assessed.

### 5. GameNetworkingSockets: CVE-2020-6016

[Pre-fix source, `src/steamnetworkingsockets/clientlib/steamnetworkingsockets_snp.cpp:570-584`](https://github.com/ValveSoftware/GameNetworkingSockets/blob/e950c994de831c02972e4d11495ca83146b9714b/src/steamnetworkingsockets/clientlib/steamnetworkingsockets_snp.cpp#L570-L584) passes a peer-controlled unreliable-segment offset and size onward without the new upper bounds. The patch checks the offset-plus-size in widened arithmetic and caps individual segment size.

NVD directly names the fix and versions before 1.2.0. Its CNA CWE-590 and NVD CWE-787 classifications differ. CVE-2020-6017 shares this fixing commit in the existing survey; do not count it as an independent pair without separately establishing an independent case.

### 6. GameNetworkingSockets: CVE-2020-6018

[Pre-fix source, `src/common/crypto_libsodium.cpp:69-87`](https://github.com/ValveSoftware/GameNetworkingSockets/blob/d885e72b436b0f76d73c8926de7368c1a2fad173/src/common/crypto_libsodium.cpp#L69-L87) calls the decryption API without checking the caller's output capacity. The patch rejects insufficient capacity; it also changes the encryption wrapper.

NVD directly names the fix and versions before 1.2.0, **only when compiled using libsodium**. A different crypto backend would not exercise this case. Keep this in the same eventual tuning/holdout group as the other GameNetworkingSockets case.

### 7. Minetest: CVE-2022-35978

[Pre-fix source, `src/script/lua_api/l_settings.cpp:30-58`](https://github.com/luanti-org/luanti/blob/bccaf5fc2d11c31615d64b9bca91f908d06b7044/src/script/lua_api/l_settings.cpp#L30-L58) protects `secure.*` and some map-generation settings but not the main-menu script setting. The patch adds `main_menu_script` and other settings to the non-main-menu deny list.

The [maintainer advisory](https://github.com/luanti-org/luanti/security/advisories/GHSA-663q-pcjw-27cc) links the fix and identifies 5.6.0 as patched. The scenario is a **single-player mod**, followed by returning to the unsandboxed menu; do not recast it as a generic remote server exploit. The current advisory and NVD also disagree on CVSS attack-vector details. No severity-based ranking is inferred here.

### 8. ioquake3: CVE-2017-11721

[Pre-fix source, `code/qcommon/msg.c:163-229`](https://github.com/ioquake/ioq3/blob/2d6171f44c72177a4b996eb721f353839fb5273d/code/qcommon/msg.c#L163-L229) reads message data and Huffman bits without the added end checks. The patch changes `msg.c`, `huffman.c`, and their declarations in `qcommon.h`, and also tightens writes.

NVD directly links the fixing commit. Do not reduce a future case to a single added guard or drop the supporting Huffman changes. NVD says crafted network packet; the specific client/server harness position remains to be established.

### 9. Teeworlds: CVE-2019-10879

[Pre-fix source, `src/engine/shared/datafile.cpp:130-146`](https://github.com/teeworlds/teeworlds/blob/40bedbecbd004d13e435d79fb7be3f3d55787d9a/src/engine/shared/datafile.cpp#L130-L146) derives allocation sizes from file header counts using unsigned accumulators. The patch widens the accumulators and rejects oversized or negative metadata.

NVD references [teeworlds/teeworlds#2070](https://github.com/teeworlds/teeworlds/issues/2070), not a commit. The issue's closing event identifies `4d529dcd2d01022e979ebfa0b91167dee37cdb8e`, and the commit message names that issue. **Word-size and intermediate-arithmetic behavior must be checked before calling the post-fix revision a valid control**; assigning a result to a wider accumulator is not itself proof that every intermediate expression is safe.

### 10. rAthena: CVE-2025-58448

[Pre-fix source, `src/web/partybooking_controller.cpp:238-259`](https://github.com/rathena/rathena/blob/2f5248b9cd9a8c6b42422ddecfc4cc2cd0e69e4b/src/web/partybooking_controller.cpp#L238-L259) inserts `WorldName` into the party-booking delete query without SQL escaping. The patch escapes the value before constructing the query.

Both NVD and the [maintainer advisory](https://github.com/rathena/rathena/security/advisories/GHSA-x99j-36m7-4vv7) identify the exact fix. This is the **optional web-server component** and requires its database environment for behavioral validation. The handler calls `isAuthorized`; the advisory's no-privileges CVSS value is not enough to infer the application's exact reachable authentication state.

## Historical licence evidence

The licence files below were read at each pair's pre-fix commit. None of the ten fixes changes those licence files; the complete changed-file lists establish continuity to the immediate post-fix revision. File-level grants were also read where they clarify "or later". This is source-licence research, not legal clearance for redistributing complete games or their dependencies.

| Project | Evidence at the historical revision | Interpretation and limits |
| --- | --- | --- |
| Chocolate Doom | [File grant, lines 4-7](https://github.com/chocolate-doom/chocolate-doom/blob/5bf73c4864fedb6b97b27bf302435a1168ba8f4c/src/net_structrw.c#L4-L7); [COPYING.md](https://github.com/chocolate-doom/chocolate-doom/blob/5bf73c4864fedb6b97b27bf302435a1168ba8f4c/COPYING.md) | GPL-2.0-or-later, explicitly in the affected file. Does not establish rights to separate game WAD assets. |
| Minetest / Luanti | [Inventory-pair LICENSE.txt](https://github.com/luanti-org/luanti/blob/d28f1b01707dfa15e770096a26495452513bc56f/LICENSE.txt); [sandbox-pair LICENSE.txt](https://github.com/luanti-org/luanti/blob/bccaf5fc2d11c31615d64b9bca91f908d06b7044/LICENSE.txt); [sandbox file grant](https://github.com/luanti-org/luanti/blob/bccaf5fc2d11c31615d64b9bca91f908d06b7044/src/script/lua_api/l_settings.cpp#L5-L8) | LGPL-2.1-or-later for Minetest source. Media and bundled libraries have separate terms, including CC BY-SA variants and an Apache-2.0 media exception. |
| Akashi | [File grant, lines 5-8](https://github.com/AttorneyOnline/akashi/blob/78f3e1d3d175c94c14734b3b2d0a3f1167eec2f7/core/src/packets.cpp#L5-L8); [LICENSE.md](https://github.com/AttorneyOnline/akashi/blob/78f3e1d3d175c94c14734b3b2d0a3f1167eec2f7/LICENSE.md) | AGPL-3.0-or-later, explicitly in the affected file. Modified network-service use requires particular attention to AGPL obligations; original game artwork is not cleared by this source grant. |
| Teeworlds | [2016 license.txt](https://github.com/teeworlds/teeworlds/blob/3e1d02283896d4b03e1ab9f9ef20ce4c30c8a0cd/license.txt); [2019 license.txt](https://github.com/teeworlds/teeworlds/blob/40bedbecbd004d13e435d79fb7be3f3d55787d9a/license.txt) | Zlib source grant confirmed from text despite GitHub's `NOASSERTION`. Both exclude bundled libraries from that blanket grant. The 2019 file separately assigns most `data`/`datasrc` content CC-BY-SA-3.0 and excludes the font; the 2016 file does not make that same explicit asset declaration. |
| GameNetworkingSockets | [CVE-2020-6016 LICENSE](https://github.com/ValveSoftware/GameNetworkingSockets/blob/e950c994de831c02972e4d11495ca83146b9714b/LICENSE); [CVE-2020-6018 LICENSE](https://github.com/ValveSoftware/GameNetworkingSockets/blob/d885e72b436b0f76d73c8926de7368c1a2fad173/LICENSE) | BSD-3-Clause. Both historical files have Git blob `9aa7a768643f22128fc12ba8062634fadf8d889e`. Preserve notices and the non-endorsement condition; dependencies retain their own licences. |
| ioquake3 | [File grant, lines 7-10](https://github.com/ioquake/ioq3/blob/2d6171f44c72177a4b996eb721f353839fb5273d/code/qcommon/msg.c#L7-L10); [COPYING.txt](https://github.com/ioquake/ioq3/blob/2d6171f44c72177a4b996eb721f353839fb5273d/COPYING.txt) | GPL-2.0-or-later, explicitly in the affected file. The source grant does not establish rights to separate Quake III game data. |
| rAthena | [README grant, lines 80-81](https://github.com/rathena/rathena/blob/2f5248b9cd9a8c6b42422ddecfc4cc2cd0e69e4b/README.md#L80-L81); [LICENSE](https://github.com/rathena/rathena/blob/2f5248b9cd9a8c6b42422ddecfc4cc2cd0e69e4b/LICENSE); [file notice](https://github.com/rathena/rathena/blob/2f5248b9cd9a8c6b42422ddecfc4cc2cd0e69e4b/src/web/partybooking_controller.cpp#L1-L2) | GNU GPL v3 confirmed. The inspected project/file grants do not explicitly establish an "or later" option, so no precise `-only`/`-or-later` SPDX assertion is made. Does not clear original game clients or artwork. |

## Important correction to the existing inventory

**Do not promote the listed Godot CVE-2021-26826 pair to a negative control yet.** Its [referenced commit](https://github.com/godotengine/godot/commit/403e4fd08b0b212e96f53d926e6273e0745eaa5a) adds the RLE condition `output_pos + count * p_pixel_size > output_pos`, rather than comparing against the output-buffer limit. This raises a valid-input behavior question as well as the need to establish the intended fix.

[godotengine/godot#45701](https://github.com/godotengine/godot/pull/45701) is indeed merged, with merge commit `59ae3ea44fb205a6ba1ae1336833c9fbb186b1df`; merged status alone does not establish a sound control. The condition was read in the patch, not reproduced. This survey substitutes the separately evidenced GameNetworkingSockets CVE-2020-6018 pair and makes no further claim about Godot's later releases.

## Unity and Unreal: additional research, not extra admitted pairs

The search found a **real Unity-game CVE remediation release** and a **public Unreal Tournament component source fix**. Neither should be silently counted as another open-source source-code pair: the former changes a proprietary runtime binary, while the latter lacks an established open-source licence for the affected code.

### Unity: Daggerfall Unity is a concrete remediation example

[Daggerfall Unity](https://github.com/Interkarma/daggerfall-unity) is an open-source recreation of Daggerfall using Unity. Its [source licence is MIT](https://github.com/Interkarma/daggerfall-unity/blob/master/LICENSE), and its [README](https://github.com/Interkarma/daggerfall-unity/blob/master/README.md) requires separate DOS Daggerfall game data. Current repository metadata reports 143,983 KB, approximately **0.147439 GB**.

The project explicitly associates its [v1.1.1-cve-2025 release](https://github.com/Interkarma/daggerfall-unity/releases/tag/v1.1.1-cve-2025) with [Unity's CVE-2025-59489 advisory](https://unity.com/security/sept-2025-01). The release says it replaced the `UnityPlayer` file and is otherwise unchanged from [v1.1.1](https://github.com/Interkarma/daggerfall-unity/releases/tag/v1.1.1). This is stronger evidence than merely assuming that every Unity game is affected.

| Daggerfall Unity package | Original v1.1.1 | CVE-remediation release | Interpretation |
| --- | ---: | ---: | --- |
| Windows x64 ZIP | 50,239,571 bytes / **0.050240 GB** | 50,240,819 bytes / **0.050241 GB** | A documented runtime-binary remediation example, not a game-source fixing commit. |
| Linux x64 ZIP | 58,809,717 bytes / **0.058810 GB** | 58,809,717 bytes / **0.058810 GB** | The maintainer explicitly says the Linux package was unchanged and reuploaded. Do not label this a before/after fix pair. Equal size alone would not prove identical bytes. |

Unity's advisory covers affected built applications on multiple platforms and offers either rebuilding/redeploying with a fixed editor or using its binary-patching mechanism. The Daggerfall release's Linux risk commentary does not supersede Unity's platform advisory. A source-code-only review of Daggerfall's MIT C# code would not expose the actual `UnityPlayer` implementation change.

**Disposition:** useful if a separately authorized binary/dependency-remediation experiment is wanted; not an additional T-067 source fix pair. No binary was downloaded or compared.

### Unity: Unitystation is open source, but not a verified CVE pair

[Unitystation](https://github.com/unitystation/unitystation) is a Unity multiplayer-game project. Its [README](https://github.com/unitystation/unitystation/blob/develop/README.md) specifies AGPL v3 for code after its documented 2017 licence transition, GPL v3 for earlier code, and generally CC-BY-SA-3.0 for assets unless otherwise indicated. It currently names Unity 6000.2.10f1 and warns that first import can take substantial time.

Current metadata reports 4,015,526 KB, approximately **4.111899 GB**: it is **not a small-first choice** compared with Akashi. The [0.1.3 GitHub release](https://github.com/unitystation/unitystation/releases/tag/0.1.3) has a Linux ZIP of 61,073,939 bytes (**0.061074 GB**), but that package is not a size estimate for the current source project or Unity editor installation.

A targeted repository issue search for `CVE` returned no matches; the broader search did not establish a published game-code CVE and fixing commit. This is a search gap, not evidence that the project is vulnerability-free.

### Unreal Tournament 3: a small public source-fix lead, blocked on licence

[UT3 WebAdmin](https://github.com/elmuerte/UT3-WebAdmin) is a server-administration component for the actual Unreal Tournament 3 game, written in UnrealScript. Its archived public repository reports 1,552 KB, approximately **0.001589 GB**. That is the component only, not Unreal Tournament 3 or the engine.

[CVE-2008-4243](https://nvd.nist.gov/vuln/detail/CVE-2008-4243) identifies directory traversal in WebAdmin before 1.7. The [original advisory](https://aluigi.altervista.org/adv/ut3webown-adv.txt) records that WebAdmin 1.7 fixed it. Public history supplies this candidate identity:

| Pre-fix | Security-fix commit | Public evidence |
| --- | --- | --- |
| [`6b3c0b9cb616ec5f1bf29b73d328ddbadeb47532`](https://github.com/elmuerte/UT3-WebAdmin/commit/6b3c0b9cb616ec5f1bf29b73d328ddbadeb47532) | [`0e1c49600ccdc471ad781388c55f096476a97ea1`](https://github.com/elmuerte/UT3-WebAdmin/commit/0e1c49600ccdc471ad781388c55f096476a97ea1) | Single-parent commit dated 2008-09-21, message "security fixes"; adds URI normalization to `UTImageServer.uc` and a v1.7 security-fix changelog entry. |

The [pre-fix file](https://github.com/elmuerte/UT3-WebAdmin/blob/6b3c0b9cb616ec5f1bf29b73d328ddbadeb47532/WebAdmin/Classes/UTImageServer.uc#L1-L14) and patch were read. The immediate follow-up `5cac4bc48106e26bc4ecb2744b6ab40c076b28ff` changes only whitespace in this particular file, although it changes other components. Thus there is a concrete source trail; it would be incorrect to describe this as necessarily binary-only or as having no public source history.

**Licence blocker:** the affected file carries an Epic Games "All Rights Reserved" header, the repository has no detected project licence, and no applicable open-source grant was established. The jQuery licence elsewhere is not a licence for UnrealScript game code. Public visibility alone does not authorize corpus redistribution. It also requires a UE3/UT3 environment and UnrealScript coverage, neither validated here.

**Disposition:** retain as a licence-blocked Unreal-game component lead, outside the ten open-source candidates. The upstream release/advisory association is established, but buildability, fix completeness, precise release-branch equivalence, and legal reuse remain unverified.

### Modern Unreal: OpenTournament is public, not permissively open source

[OpenTournament](https://github.com/OpenTournament/OpenTournament) is a public FPS game project whose [project descriptor](https://github.com/OpenTournament/OpenTournament/blob/master/OpenTournament.uproject) names Unreal Engine 5.7. Reported Git storage is 15,428 KB, approximately **0.015798 GB**, but that number is especially misleading as a full-project estimate: its [`.gitattributes`](https://github.com/OpenTournament/OpenTournament/blob/master/.gitattributes) routes `.uasset`, `.umap`, `.dll`, and `.zip` files through Git LFS. Actual asset and engine size was not obtained. No GitHub release was returned.

Its [current licence](https://github.com/OpenTournament/OpenTournament/blob/master/LICENSE) says "All Rights Reserved" and permits source use only for development of the official Open Tournament project. Its [README](https://github.com/OpenTournament/OpenTournament/blob/master/README.md) additionally warns against redistribution without approval. **Do not classify it as MIT or as an unrestricted open-source benchmark target.** No game-code CVE fix pair was verified.

### Search coverage and limits

Primary NVD keyword queries for `Unity` and `Unreal` were inspected, with all three Unity result pages retrieved (228 records) and the complete Unreal result page retrieved (59 records). These totals include unrelated products such as Cisco/Dell Unity and UnrealIRCd; they are not counts of game vulnerabilities. Web searches, targeted repository searches, public source history, release notes, and licence files were used to investigate specific leads.

Legacy Unreal-game CVEs do exist, including [CVE-2004-0608](https://nvd.nist.gov/vuln/detail/CVE-2004-0608) and [CVE-2010-2702](https://nvd.nist.gov/vuln/detail/CVE-2010-2702), but those records alone do not supply a verified open-source pair. Conversely, Unity development-tool CVEs and blueprintUE web-tool CVEs are not vulnerabilities in games and were not counted.

The search did **not establish another fully qualified open-source Unity/Unreal game-code pair**. This is not a universal claim that none exists. Direct retrieval of Epic's engine-source access and EULA pages returned HTTP 403, so no fresh engine-licence clearance is asserted. No private Epic source access, package acquisition, decompilation, or live review was attempted.

## Admission boundary

All ten entries have a published CVE association, a fixing commit with its direct parent, source locations read at that parent, a reviewed patch, and historical source-licence evidence. That verifies the **research links and identities**, not exploitability, buildability, fix completeness, or benign-input preservation.

For a later user-owned acquisition and admission step, each selected pair still needs the intended upstream branch and build configuration established, behavior checked on both revisions, and narrowly scoped pre-fix expectations and post-fix controls kept outside the target. A fixed revision is not a globally vulnerability-free negative sample. The map-arithmetic, backend-specific crypto, historical toolchain, and optional web-server qualifications above must remain visible.

No private holdout has been selected. These public CVEs may already occur in model training data, and this survey itself exposes their explanations. Future split design should group related project/fix families rather than scatter adjacent revisions across tuning and holdout sets, and record holdout access/use independently. Public-CVE coverage cannot establish a contamination-free private benchmark.

The research used checkout `60e562e0c2f8672061007d67d25bef2282f44132`. Publication adds this shortlist, including its size and Unity/Unreal addendum, and navigation references only; candidate admission, target acquisition, and corpus changes remain outside this document.
