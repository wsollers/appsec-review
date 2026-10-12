---
id: network_api_surface
version: 1
covers: ["cwe:346", "cwe:441", "cwe:444", "cwe:601", "cwe:918", "cwe:942", "cwe:1021", "cwe:1385", "func:net:*", "func:exec:ipc"]
standards: ["cwe", "capec", "attack", "asvs5", "api-top10-2023", "top10-2025"]
max_tokens: 1500
---
## Viewpoint
An API and network-edge attacker. The attack surface is every listener, route, RPC method,
socket, outbound request, and local IPC endpoint. The questions are what is exposed, to whom,
what the server can be made to fetch, and which origins the browser is told to trust.

## Coverage
GENERATED

## Likely failure modes
- SSRF: `requests.get(url)`, `HttpClient`, `fetch`, `curl_exec`, `URL.openStream` on a
  user-supplied URL or host; webhooks, image fetchers, PDF renderers, import-from-URL features;
  redirects followed into `169.254.169.254`, `localhost`, or internal names; DNS rebinding between
  validation and connect; `gopher://`, `file://` schemes.
- Allowlists implemented with `startsWith`, substring, or regex on the URL string instead of the
  parsed and resolved host (`https://good.com@evil`, `good.com.evil.net`).
- Open redirects: `redirect(request.args["next"])`, `Location` from a parameter, protocol-relative
  `//evil`.
- CORS: `Access-Control-Allow-Origin` reflecting the request `Origin` with
  `Allow-Credentials: true`, `null` origin allowed, suffix-matching origin checks.
- WebSocket handshakes without an `Origin` check on cookie-authenticated connections.
- Exposure: debug or admin listeners (`/actuator`, `pprof`, `/debug/vars`, gRPC reflection,
  GraphQL introspection) bound to `0.0.0.0`; internal services trusting `X-Forwarded-For`.
- Request smuggling and desync between proxy and backend (conflicting `Content-Length` and
  `Transfer-Encoding`).
- GraphQL depth, alias, and batching limits absent; excessive data in responses.
- Local IPC: Unix sockets or named pipes with permissive modes, D-Bus or XPC services without
  peer credential checks.
- Missing frame-ancestor protections on sensitive pages (clickjacking).

## Effective controls
- Outbound fetch through a resolver that validates the resolved IP against deny ranges at connect
  time, disables redirects or revalidates each hop, and restricts schemes; egress proxies.
- Redirect targets restricted to relative paths or an exact host allowlist.
- CORS with a fixed origin list and no credentialed wildcard.
- Admin and debug endpoints on a separate loopback or management listener.
- Peer credential checks (`SO_PEERCRED`, `GetNamedPipeClientProcessId`) and restrictive socket modes.
- `Content-Security-Policy: frame-ancestors`, `X-Frame-Options`.

## False positives
- Server-side fetches of URLs taken from operator configuration, not requests.
- Redirects to a value chosen from a server-side map.
- `Access-Control-Allow-Origin: *` on public, unauthenticated, non-credentialed resources.
- Introspection enabled only in development profiles that the deployment does not use.

## Evidence by predicate
- `affected_construct`: the outbound client call, redirect, CORS configuration, listener bind, or
  IPC endpoint.
- `attacker_input_control`: the URL, host, header, origin, or message field the remote party sets.
- `source_to_sink_reachability`: the route from the request to the client call or response header,
  including job queues that perform the fetch later.
- `missing_or_ineffective_guard`: string-based allowlists, validation before resolution, redirects
  followed unchecked, reflected origins.
- `configuration_enables`: bind addresses, proxy and egress rules, profile flags enabling debug
  endpoints, cloud metadata service version.
- `security_impact`: internal network or metadata credential access, token theft through redirect,
  cross-origin data read, or reachability of internal-only functions.

## Hand-offs
TLS certificate validation goes to `cryptography_data_protection`. Authentication of API callers
goes to `authentication_session`. Per-object API authorization goes to
`authorization_access_control`. Ingress and cloud load balancer exposure go to
`cloud_container_deployment`.
