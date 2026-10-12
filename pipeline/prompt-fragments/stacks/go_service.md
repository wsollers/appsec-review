---
id: go_service
version: 1
covers: []
standards: ["cwe", "asvs5", "api-top10-2023"]
max_tokens: 1500
---
## Runtime and framework model
A Go service: `net/http` with `ServeMux` (Go 1.22 pattern routing), chi, gorilla/mux, gin, echo,
fiber, or grpc-go; often a Kubernetes controller or CLI. Memory safe except for `unsafe`, cgo, and
data races; every request runs in its own goroutine, so shared maps and slices need explicit
synchronization. Errors are values; ignored errors are common.

## Trust and interface layer
- Entry points: `http.HandlerFunc`s, framework handlers, gRPC methods, message consumers, CLI
  flags, and controller reconcile loops reading cluster objects that other users can create.
- Middleware chains wrap handlers; authentication is middleware, so route groups registered
  outside the wrapped router skip it.
- `json.Decoder` maps bodies into structs; unknown fields are ignored unless
  `DisallowUnknownFields` is set.

## Idiomatic security mechanisms
- `database/sql` placeholders (`$1`, `?`), sqlx named parameters, GORM with struct conditions.
- `html/template` contextual escaping (not `text/template` for HTML).
- `exec.Command(name, args...)` without a shell.
- `http.MaxBytesReader`, `io.LimitReader`, `http.Server` `ReadHeaderTimeout`/`ReadTimeout`/
  `WriteTimeout`, `context.WithTimeout`.
- `crypto/rand`, `crypto/subtle.ConstantTimeCompare`, `tls.Config` defaults with
  `MinVersion: tls.VersionTLS12`.
- `os.Root` (Go 1.24) or `filepath.Rel`/`filepath.IsLocal` checks for containment.

## Stack-specific pitfalls
- `filepath.Join(base, userPath)` assumed safe: it cleans `..` but does not keep the result under
  `base`; `http.ServeFile` with request paths; archive extraction without `IsLocal`.
- `fmt.Sprintf` into SQL; GORM `Where("name = " + v)` or `Raw` with concatenation.
- `text/template` for HTML, `template.HTML(userInput)` casts.
- `http.Server` without timeouts (slowloris); `ioutil.ReadAll(r.Body)` without a size cap.
- `InsecureSkipVerify: true`; `math/rand` for tokens.
- Data races on maps in handlers or caches (fatal concurrent map writes become a DoS).
- `net/http/pprof` imported for side effects, registering `/debug/pprof` on the default mux.
- Error ignored from authorization or signature-verification helpers (`ok, _ := verify(...)`
  patterns, or `err` shadowing).
- Goroutine leaks from unbounded per-request goroutines or unread channels.
- cgo calls passing Go slices to C that retain the pointer, or `unsafe.Pointer` arithmetic
  over byte slices from requests.

## Build and deployment facts to check
- Go version in `go.mod` (`go` and `toolchain` lines) and `go.sum` presence; resolved module
  versions against advisories (`govulncheck` reachability where available).
- Build tags and `CGO_ENABLED`, which change compiled files and memory safety.
- Whether `-race` tests exist; whether the default mux is served publicly.
- Container image (distroless or scratch, user id) and listen addresses.
