package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// staleScanDays is the age past which `cryptamap serve` warns that the served
// scan may no longer reflect the live environment (crypto posture drifts as
// resources are created/rotated). Advisory only — serve still runs.
const staleScanDays = 14

// scanFileAgeDays returns whole days between modTime and now (floored at 0).
func scanFileAgeDays(modTime time.Time) int {
	d := int(time.Since(modTime).Hours() / 24)
	if d < 0 {
		return 0
	}
	return d
}

// serveFlags configure the local dashboard server.
type serveFlags struct {
	dir  string
	port int
	demo bool
}

// newServeCmd builds the `cryptamap serve` subcommand. It serves the embedded
// dashboard Single-Page-App over HTTP, wiring the dashboard's local-data
// contract (config.json + /mock/org-cbom.json + /mock/roadmap.json — see
// dashboard/src/services/api.ts) onto a local scan-output directory. No AWS,
// no network: it reads the CBOM + roadmap a prior `cryptamap` / `org-merge-files`
// run wrote to --dir and renders them entirely in-browser.
//
// SECURITY INVARIANT: the listener binds to 127.0.0.1 ONLY. There is
// deliberately NO bind-all / --host / --listen flag. CryptaMap's data is a
// cryptographic inventory of an AWS org (the very map an attacker wants), so the
// local-first model keeps it on the operator's machine: a loopback-only bind
// makes accidental network exposure of the inventory structurally impossible.
// Reaching it from another host is an explicit, out-of-band choice
// (e.g. an SSH tunnel), never a flag this tool offers.
func newServeCmd() *cobra.Command {
	f := serveFlags{}
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Serve the dashboard locally (127.0.0.1) over a local CBOM + roadmap",
		Long: `serve runs the CryptaMap dashboard as a local web app, reading a CBOM +
PQC roadmap from a local scan-output directory and rendering them in-browser.

It wires the dashboard's local-data contract onto your --dir:

  /config.json            synthesized as {"apiBase":"","mockMode":true}
  /mock/org-cbom.json     your --dir CBOM   (org-cbom.json or newest *.cbom.json)
  /mock/roadmap.json      your --dir roadmap (roadmap.json or newest *.roadmap.json)

NOTE on the /mock/ route names + mockMode flag: these name the dashboard's
static-file TRANSPORT, NOT the data's authenticity. serve always feeds your REAL
scan output through them; the dashboard derives its "Live scan / Demo data" label
from the CBOM's own cryptamap:mode provenance (live/merged/mock), so a real scan
served here is correctly shown as live, never "demo". (The route names are kept
only to match the committed dashboard contract; data authenticity is data-driven.)

The embedded dashboard is a BrowserRouter SPA, so any unknown path falls back to
index.html (deep links like /roadmap do not 404).

REAL is the default. serve shows YOUR scan from --dir. Pass --demo ONLY to show
the bundled synthetic sample data (for demos to stakeholders / evaluators with no
scan yet) — the demo CBOM is mode="mock", so the dashboard clearly flags it as
"Demo data". A real customer never needs --demo; running a scan and pointing serve
at its output is the whole product.

SECURITY: the server binds to 127.0.0.1 ONLY — there is no option to bind to
other interfaces. CryptaMap output is a cryptographic inventory of your AWS org;
keeping it loopback-only is a hard invariant of the local-first model. Expose it
to another host only via an explicit tunnel (e.g. ssh -L), never by flag.

It makes NO AWS or network calls.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runServe(cmd, f)
		},
	}
	cmd.Flags().StringVar(&f.dir, "dir", "./dist/scan-output", "local directory holding the CBOM + roadmap to serve (your REAL scan output)")
	cmd.Flags().BoolVar(&f.demo, "demo", false, "serve bundled SYNTHETIC sample data instead of --dir (for demos; the dashboard flags it as Demo data)")
	cmd.Flags().IntVar(&f.port, "port", 0, "TCP port on 127.0.0.1 (0 = OS-assigned ephemeral; the chosen URL is printed)")
	return cmd
}

func runServe(cmd *cobra.Command, f serveFlags) error {
	var mux *http.ServeMux
	var cbomPath, roadmapPath string
	var arts []artifact

	if f.demo {
		// DEMO mode: serve the bundled SYNTHETIC sample data embedded in the
		// binary (webdist/mock/*.json, mode="mock"), NOT --dir. This is the only
		// path that does not require a real scan; the demo CBOM's own provenance
		// makes the dashboard flag it as "Demo data". No --dir is read.
		if _, err := fs.Stat(webDist, "webdist/mock/org-cbom.json"); err != nil {
			return fmt.Errorf("--demo: no bundled demo data embedded (build with `make build-serve`): %w", err)
		}
		mux = newDemoMux()
		cbomPath, roadmapPath = "(embedded demo)", "(embedded demo)"
	} else {
		// REAL mode (default): resolve the customer's CBOM + roadmap from --dir up
		// front so a missing/empty --dir fails loudly at startup rather than as a
		// confusing in-browser 404 later.
		var err error
		cbomPath, err = findLatest(f.dir, "org-cbom.json", ".cbom.json")
		if err != nil {
			return fmt.Errorf("locate CBOM in --dir=%s: %w (run a scan first, or pass --demo for sample data)", f.dir, err)
		}
		roadmapPath, err = findLatest(f.dir, "roadmap.json", ".roadmap.json")
		if err != nil {
			return fmt.Errorf("locate roadmap in --dir=%s: %w (run a scan first, or pass --demo for sample data)", f.dir, err)
		}
		// Discover the full downloadable artifact set in --dir (CBOM, ASFF,
		// PQCC workbook, HTML report, roadmaps, coverage). Missing kinds are
		// omitted; the manifest + per-artifact routes are built from this.
		arts = findArtifacts(f.dir)
		mux = newServeMux(cbomPath, roadmapPath, arts)
	}

	// Bind explicitly to a loopback listener so the OS assigns an ephemeral port
	// when --port=0 and we can print the exact URL. 127.0.0.1 is hard-coded — see
	// the command doc: there is no bind-all option by design.
	addr := fmt.Sprintf("127.0.0.1:%d", f.port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", addr, err)
	}

	// The actual bound port (the OS picks one when --port=0); the Host-header
	// allowlist is built from it so an in-browser request to the printed URL
	// passes while a rebound DNS name (evil.com → 127.0.0.1) is rejected.
	boundPort := ln.Addr().(*net.TCPAddr).Port

	url := fmt.Sprintf("http://%s/", ln.Addr().String())
	fmt.Fprintf(cmd.OutOrStdout(), "CryptaMap dashboard serving at %s\n", url)
	if f.demo {
		fmt.Fprintln(cmd.OutOrStdout(), "  Data:    SYNTHETIC DEMO (--demo) — not a real scan; the dashboard flags it as Demo data")
	} else {
		fmt.Fprintf(cmd.OutOrStdout(), "  CBOM:    %s\n", cbomPath)
		fmt.Fprintf(cmd.OutOrStdout(), "  Roadmap: %s\n", roadmapPath)
		// Stale-scan guard: surface the CBOM's age so an operator viewing a
		// weeks-old scan is told rather than silently trusting drift. (Crypto
		// posture changes as resources are created/rotated; a stale inventory
		// misleads.)
		if st, statErr := os.Stat(cbomPath); statErr == nil {
			age := scanFileAgeDays(st.ModTime())
			fmt.Fprintf(cmd.OutOrStdout(), "  Scan age: %d day(s) old\n", age)
			if age >= staleScanDays {
				fmt.Fprintf(cmd.OutOrStdout(),
					"  ⚠ WARNING: this scan is %d days old (>= %d) — re-run `cryptamap` for a current inventory before relying on it.\n",
					age, staleScanDays)
			}
		}
		// Discoverability: list every downloadable artifact found in --dir (one
		// line each) + the dir, so the CLI alone tells the operator where each
		// deliverable is and which route it is served at. (See
		// docs/ARTIFACT-EXPORT-DESIGN.md §6.)
		if len(arts) > 0 {
			fmt.Fprintf(cmd.OutOrStdout(), "  Artifacts in %s (downloadable under /artifacts/):\n", f.dir)
			for _, a := range arts {
				fmt.Fprintf(cmd.OutOrStdout(), "    %-32s %s  (%s)\n", a.route, a.filename, a.label)
			}
		}
	}
	fmt.Fprintln(cmd.OutOrStdout(), "  (loopback only — Ctrl-C to stop)")

	// Wrap the mux in the Host-header allowlist (DNS-rebinding defense) and set
	// explicit timeouts so a slow/stuck client cannot tie up the loopback server
	// indefinitely. The listener is already 127.0.0.1-only; the allowlist closes
	// the residual DNS-rebinding gap (a page on evil.com whose A record points at
	// 127.0.0.1 would otherwise reach this server with Host: evil.com).
	srv := &http.Server{
		Handler:           loopbackHostGuard(mux, boundPort),
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// loopbackHostGuard wraps next with a Host-header allowlist: only requests whose
// Host names a loopback identity (localhost / 127.0.0.1 / [::1]), optionally with
// the bound port, are served; everything else gets a 403. This is a defense
// against DNS rebinding — the listener is already 127.0.0.1-only, but a page on a
// hostile origin whose DNS resolves to 127.0.0.1 could otherwise reach this
// server and read the cryptographic inventory via a Host header it controls. The
// allowlist (not a denylist) means any unexpected Host is rejected by default.
func loopbackHostGuard(next http.Handler, port int) http.Handler {
	// Permitted host:port (and bare-host, since the Host header may omit a default
	// port) forms. r.Host has no scheme; build the explicit set we accept.
	allowed := map[string]struct{}{}
	for _, h := range []string{"localhost", "127.0.0.1", "[::1]"} {
		allowed[h] = struct{}{}
		allowed[fmt.Sprintf("%s:%d", h, port)] = struct{}{}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := allowed[r.Host]; !ok {
			http.Error(w, "forbidden: CryptaMap serves loopback hosts only", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// newServeMux builds the HTTP routes: the dashboard's local-data contract
// (config.json + the two /mock/ artifacts) mapped onto on-disk files, the
// downloadable artifact set under /artifacts/*, with the embedded SPA (and its
// deep-link fallback) serving everything else. arts is the set found in --dir
// (see findArtifacts); each is exposed at its fixed route as an attachment
// download, and all are listed at /artifacts/manifest.json for the UI.
func newServeMux(cbomPath, roadmapPath string, arts []artifact) *http.ServeMux {
	mux := http.NewServeMux()

	// Synthesized runtime config: empty apiBase + mockMode=true sends the
	// dashboard down its local-data path (fetch /mock/org-cbom.json +
	// /mock/roadmap.json) instead of any live ${apiBase} endpoint.
	mux.HandleFunc("/config.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"apiBase":"","mockMode":true}`))
	})

	// The two mock artifacts the dashboard fetches in mock mode, served from the
	// operator's --dir. http.ServeFile sets Content-Type + handles conditional
	// requests; the paths are fixed (resolved at startup), so there is no
	// user-controlled path traversal here.
	mux.HandleFunc("/mock/org-cbom.json", fileServer(cbomPath))
	mux.HandleFunc("/mock/roadmap.json", fileServer(roadmapPath))

	// Downloadable artifact set: the manifest the UI reads, plus one fixed route
	// per artifact present on disk. Each route serves its file (fixed path → no
	// traversal) as an attachment under the real timestamped filename.
	mux.HandleFunc("/artifacts/manifest.json", artifactManifestHandler(arts))
	for _, a := range arts {
		mux.HandleFunc(a.route, artifactDownload(a))
	}

	// Everything else: the embedded SPA with index.html fallback so BrowserRouter
	// deep links (e.g. /roadmap, /accounts/123) resolve to the app shell.
	mux.Handle("/", spaHandler())

	return mux
}

// newDemoMux serves the bundled SYNTHETIC demo data embedded in the binary
// (webdist/mock/*.json — the mode="mock" sample the dashboard build copied from
// dashboard/public/mock). It reads NO --dir and touches NO customer file: --demo
// is for showing the tool with zero real scan. config.json is synthesized the
// same way; the /mock/*.json + SPA assets all come from the embedded webdist via
// spaHandler, so there is exactly one bundled data set and it can never be
// confused with a real scan (its CBOM is mode="mock").
func newDemoMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/config.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"apiBase":"","mockMode":true}`))
	})
	// /mock/org-cbom.json, /mock/roadmap.json AND the SPA assets are all served
	// straight from the embedded webdist by spaHandler (vite copied public/mock
	// into the bundle), so no on-disk file is read in demo mode.
	mux.Handle("/", spaHandler())
	return mux
}

// fileServer serves a single fixed file (Content-Type + caching handled by
// http.ServeFile), 404ing if it has since been removed.
func fileServer(path string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, path)
	}
}

// artifactDownload serves one located artifact via the same fixed-path
// http.ServeFile machinery as fileServer (no user-controlled path → no
// traversal), but adds Content-Disposition: attachment so the browser saves it
// under the REAL timestamped filename rather than the stable route name. The
// header is set before ServeFile writes the body. (http.ServeFile may also set
// Content-Type from the extension; that is harmless alongside the disposition.)
func artifactDownload(a artifact) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if a.contentType != "" {
			w.Header().Set("Content-Type", a.contentType)
		}
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", a.filename))
		http.ServeFile(w, r, a.path)
	}
}

// artifactManifestHandler serves /artifacts/manifest.json: a JSON array of the
// artifacts present on disk (in artifactKinds order), giving the UI a generic,
// demo/real-agnostic list of what to offer for download. The on-disk path is
// intentionally not exposed.
func artifactManifestHandler(arts []artifact) http.HandlerFunc {
	manifest := make([]artifactManifest, 0, len(arts))
	for _, a := range arts {
		manifest = append(manifest, artifactManifest{
			Kind:        a.kind,
			Label:       a.label,
			Route:       a.route,
			Filename:    a.filename,
			ContentType: a.contentType,
		})
	}
	body, err := json.Marshal(manifest)
	if err != nil {
		// The shape is fixed and trivially marshalable; treat failure as a bug.
		panic(fmt.Sprintf("cryptamap: marshal artifact manifest: %v", err))
	}
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}
}

// spaHandler serves the embedded dashboard bundle, falling back to index.html
// for any path that does not map to an embedded file. This is the standard
// Single-Page-App contract: client-side BrowserRouter owns the route table, so a
// hard refresh / shared deep link must still return the app shell rather than a
// 404.
func spaHandler() http.HandlerFunc {
	// Root the embedded FS at the webdist subtree so request paths map directly to
	// bundle files (the embed.FS otherwise prefixes every entry with "webdist/").
	sub, err := fs.Sub(webDist, "webdist")
	if err != nil {
		// embed.FS with a constant root never fails; treat as a build invariant.
		panic(fmt.Sprintf("cryptamap: embedded webdist subtree: %v", err))
	}
	fileSrv := http.FileServer(http.FS(sub))

	return func(w http.ResponseWriter, r *http.Request) {
		// Normalize and resolve the requested asset against the embedded FS. A
		// real file (index.html, /assets/app-*.js, /cryptamap.svg, …) is served
		// directly; anything else is a client-side route → serve index.html.
		name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
		if name == "" {
			name = "index.html"
		}
		if f, err := sub.Open(name); err == nil {
			info, statErr := f.Stat()
			_ = f.Close()
			if statErr == nil && !info.IsDir() {
				fileSrv.ServeHTTP(w, r)
				return
			}
		}
		serveIndex(w, r, sub)
	}
}

// serveIndex writes the embedded index.html as the SPA fallback body. It is
// served with a 200 (it IS the app shell for a valid client-side route), not a
// 404.
func serveIndex(w http.ResponseWriter, r *http.Request, sub fs.FS) {
	b, err := fs.ReadFile(sub, "index.html")
	if err != nil {
		http.Error(w, "dashboard bundle missing index.html (run `make build-serve`)", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(b)
}

// findLatest locates a file in dir for the dashboard contract: it prefers the
// exact canonical name (e.g. org-cbom.json) and otherwise falls back to the
// lexicographically-last *<suffix> match. The scan/merge writers timestamp their
// filenames (cryptamap-...-20060102T150405Z.cbom.json, cryptamap-org-<ts>...),
// so the lexicographic-last entry is the most recent run. Returns an error if
// neither is present so the caller can fail loudly at startup.
func findLatest(dir, exact, suffix string) (string, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", fmt.Errorf("%s is not a directory", dir)
	}

	if exact != "" {
		p := filepath.Join(dir, exact)
		if st, statErr := os.Stat(p); statErr == nil && !st.IsDir() {
			return p, nil
		}
	}

	matches, err := filepath.Glob(filepath.Join(dir, "*"+suffix))
	if err != nil {
		return "", err
	}
	// Drop directories that happen to match the suffix; keep only regular files.
	files := matches[:0]
	for _, m := range matches {
		if st, statErr := os.Stat(m); statErr == nil && !st.IsDir() {
			files = append(files, m)
		}
	}
	if len(files) == 0 {
		return "", fmt.Errorf("no %s or *%s file found", exact, suffix)
	}
	sort.Strings(files)
	return files[len(files)-1], nil
}

// artifact describes one downloadable scan-output file discovered on disk. kind
// is the stable identifier the UI keys on; label is the plain-English name;
// route is the fixed /artifacts/* path it is served at; filename is the basename
// of the REAL timestamped file (sent as the Content-Disposition download name);
// path is the absolute on-disk source; contentType is the response MIME type.
// Fields are unexported (internal model); the JSON manifest uses its own shape
// in artifactManifest below.
type artifact struct {
	kind        string
	label       string
	route       string
	filename    string
	path        string
	contentType string
}

// artifactManifest is the per-artifact JSON shape the UI fetches from
// /artifacts/manifest.json. It deliberately omits the on-disk path (an internal
// detail the browser must not see).
type artifactManifest struct {
	Kind        string `json:"kind"`
	Label       string `json:"label"`
	Route       string `json:"route"`
	Filename    string `json:"filename"`
	ContentType string `json:"contentType"`
}

// artifactKind statically describes one downloadable artifact type: how to find
// it in --dir (preferGlob tried first, then suffix via findLatest) and how to
// present/serve it. The order here is the order the manifest + startup output
// list artifacts in.
type artifactKind struct {
	kind        string
	label       string
	route       string
	preferGlob  string // optional glob tried before suffix (e.g. org CBOM); "" to skip
	suffix      string // findLatest suffix fallback (newest timestamped wins)
	contentType string
}

// artifactKinds is the fixed catalog of downloadable artifacts the scan/merge
// writers produce (see docs/ARTIFACT-EXPORT-DESIGN.md §2). Each maps to one
// stable /artifacts/* route; missing kinds are simply omitted from the manifest.
// The CBOM prefers the org-merge file (cryptamap-org-*.cbom.json) when present —
// it is the org-wide deliverable — else the newest per-scan *.cbom.json.
var artifactKinds = []artifactKind{
	{"cbom", "CycloneDX 1.7 CBOM", "/artifacts/cbom.json", "*-org-*.cbom.json", ".cbom.json", "application/json"},
	{"asff", "Security Hub ASFF findings", "/artifacts/findings.asff.json", "", ".asff.json", "application/json"},
	{"pqcc", "MITRE PQCC workbook", "/artifacts/report.pqcc.xlsx", "", ".pqcc.xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
	{"report", "Offline HTML report", "/artifacts/report.html", "", ".report.html", "text/html; charset=utf-8"},
	{"roadmap-json", "PQC migration roadmap (JSON)", "/artifacts/roadmap.json", "", ".roadmap.json", "application/json"},
	{"roadmap-md", "PQC migration roadmap (Markdown)", "/artifacts/roadmap.md", "", ".roadmap.md", "text/markdown; charset=utf-8"},
	{"coverage", "Coverage matrix", "/artifacts/coverage.json", "", ".coverage.json", "application/json"},
}

// findArtifacts locates, on disk in dir, the newest of each downloadable
// artifact kind (see artifactKinds), reusing the findLatest timestamped-suffix
// pattern. For the CBOM it prefers the org-merge file (preferGlob) when present.
// Missing kinds are simply omitted — a CBOM-only dir yields a one-entry slice.
// The returned slice preserves artifactKinds order. dir is never trusted as a
// served path: only the resolved per-kind file is exposed, at its fixed route.
func findArtifacts(dir string) []artifact {
	var found []artifact
	for _, k := range artifactKinds {
		p := resolveArtifact(dir, k)
		if p == "" {
			continue // kind absent from this dir — omit it
		}
		found = append(found, artifact{
			kind:        k.kind,
			label:       k.label,
			route:       k.route,
			filename:    filepath.Base(p),
			path:        p,
			contentType: k.contentType,
		})
	}
	return found
}

// resolveArtifact returns the on-disk path for one artifact kind, or "" if none
// is present. It first tries preferGlob (newest match) when set, then falls back
// to the newest *suffix file via findLatest's lexicographic-last == newest rule.
func resolveArtifact(dir string, k artifactKind) string {
	if k.preferGlob != "" {
		if p := newestGlob(filepath.Join(dir, k.preferGlob)); p != "" {
			return p
		}
	}
	// No exact canonical name for these (unlike the /mock/ contract), so pass ""
	// and let findLatest use the timestamped-suffix fallback.
	if p, err := findLatest(dir, "", k.suffix); err == nil {
		return p
	}
	return ""
}

// newestGlob returns the lexicographically-last regular file matching pattern
// (== newest, since filenames are timestamped 20060102T150405Z), or "" if none.
func newestGlob(pattern string) string {
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return ""
	}
	files := matches[:0]
	for _, m := range matches {
		if st, statErr := os.Stat(m); statErr == nil && !st.IsDir() {
			files = append(files, m)
		}
	}
	if len(files) == 0 {
		return ""
	}
	sort.Strings(files)
	return files[len(files)-1]
}
