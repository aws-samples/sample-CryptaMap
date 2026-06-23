package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestServeMuxLocalDataContract verifies the three local-data routes the
// dashboard depends on (api.ts): config.json forces mock mode, and the two
// /mock/ artifacts are served from the on-disk CBOM + roadmap.
func TestServeMuxLocalDataContract(t *testing.T) {
	dir := t.TempDir()
	cbomBody := `{"bomFormat":"CycloneDX","components":[]}`
	roadmapBody := `{"phases":[]}`
	cbomPath := filepath.Join(dir, "org-cbom.json")
	roadmapPath := filepath.Join(dir, "roadmap.json")
	if err := os.WriteFile(cbomPath, []byte(cbomBody), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(roadmapPath, []byte(roadmapBody), 0o644); err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(newServeMux(cbomPath, roadmapPath, nil))
	defer srv.Close()

	cases := []struct {
		path     string
		wantBody string
	}{
		{"/config.json", `{"apiBase":"","mockMode":true}`},
		{"/mock/org-cbom.json", cbomBody},
		{"/mock/roadmap.json", roadmapBody},
	}
	for _, tc := range cases {
		got := httpGet(t, srv.URL+tc.path)
		if strings.TrimSpace(got) != tc.wantBody {
			t.Errorf("%s = %q, want %q", tc.path, got, tc.wantBody)
		}
	}
}

// TestServeMuxSPAFallback verifies an unknown deep-link path returns the
// embedded index.html (200) so BrowserRouter routes do not 404.
func TestServeMuxSPAFallback(t *testing.T) {
	srv := httptest.NewServer(newServeMux("/dev/null", "/dev/null", nil))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/roadmap/some/deep/link")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("deep link status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "<html") {
		t.Errorf("deep link did not return the SPA index.html shell: %q", string(body))
	}
}

// TestFindLatest checks the exact-name preference and the timestamped-suffix
// fallback (lexicographic-last == most recent run).
func TestFindLatest(t *testing.T) {
	dir := t.TempDir()

	// No files yet → error.
	if _, err := findLatest(dir, "org-cbom.json", ".cbom.json"); err == nil {
		t.Fatal("expected error for empty dir")
	}

	// Two timestamped CBOMs, no canonical name → newest (lexicographic-last) wins.
	older := filepath.Join(dir, "cryptamap-scan-1-us-east-1-20260101T000000Z.cbom.json")
	newer := filepath.Join(dir, "cryptamap-scan-1-us-east-1-20260201T000000Z.cbom.json")
	for _, p := range []string{older, newer} {
		if err := os.WriteFile(p, []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := findLatest(dir, "org-cbom.json", ".cbom.json")
	if err != nil {
		t.Fatal(err)
	}
	if got != newer {
		t.Errorf("findLatest fallback = %s, want %s", got, newer)
	}

	// Canonical name present → preferred over the timestamped fallbacks.
	canonical := filepath.Join(dir, "org-cbom.json")
	if err := os.WriteFile(canonical, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err = findLatest(dir, "org-cbom.json", ".cbom.json")
	if err != nil {
		t.Fatal(err)
	}
	if got != canonical {
		t.Errorf("findLatest = %s, want canonical %s", got, canonical)
	}
}

// TestNewServeCmdNoBindAllFlag is a guard for the hard security invariant: the
// command must expose --dir and --port and MUST NOT expose any bind-all flag.
func TestNewServeCmdNoBindAllFlag(t *testing.T) {
	cmd := newServeCmd()
	if cmd.Flags().Lookup("dir") == nil {
		t.Error("missing --dir flag")
	}
	if cmd.Flags().Lookup("port") == nil {
		t.Error("missing --port flag")
	}
	for _, banned := range []string{"host", "listen", "bind", "address", "addr", "interface"} {
		if cmd.Flags().Lookup(banned) != nil {
			t.Errorf("forbidden bind-all flag --%s present (127.0.0.1 is a hard invariant)", banned)
		}
	}
}

// TestFindArtifacts verifies artifact discovery: the org CBOM is preferred over
// the per-scan CBOM, each present kind is found at its real timestamped
// filename, and absent kinds are omitted.
func TestFindArtifacts(t *testing.T) {
	dir := t.TempDir()
	write := func(name string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// A per-scan CBOM and a newer org-merge CBOM (org must win), plus ASFF and
	// the JSON roadmap. No PQCC/HTML/coverage/roadmap-md → those must be omitted.
	write("cryptamap-scan-1-us-east-1-20260101T000000Z.cbom.json")
	write("cryptamap-org-20260201T000000Z.cbom.json")
	write("cryptamap-scan-1-us-east-1-20260101T000000Z.asff.json")
	write("cryptamap-org-20260201T000000Z.roadmap.json")

	arts := findArtifacts(dir)

	byKind := map[string]artifact{}
	for _, a := range arts {
		byKind[a.kind] = a
	}
	if got := byKind["cbom"].filename; got != "cryptamap-org-20260201T000000Z.cbom.json" {
		t.Errorf("cbom = %q, want org-merge file preferred", got)
	}
	if got := byKind["asff"].filename; got != "cryptamap-scan-1-us-east-1-20260101T000000Z.asff.json" {
		t.Errorf("asff = %q", got)
	}
	if _, ok := byKind["roadmap-json"]; !ok {
		t.Error("roadmap-json missing")
	}
	for _, absent := range []string{"pqcc", "report", "roadmap-md", "coverage"} {
		if _, ok := byKind[absent]; ok {
			t.Errorf("kind %q should be omitted (no file on disk)", absent)
		}
	}
	if len(arts) != 3 {
		t.Errorf("found %d artifacts, want 3 (cbom, asff, roadmap-json)", len(arts))
	}
}

// TestServeMuxArtifactRoutes verifies the manifest lists only on-disk artifacts
// and each artifact route serves its file with a Content-Disposition attachment
// header naming the REAL timestamped filename.
func TestServeMuxArtifactRoutes(t *testing.T) {
	dir := t.TempDir()
	cbomName := "cryptamap-org-20260201T000000Z.cbom.json"
	cbomBody := `{"bomFormat":"CycloneDX"}`
	if err := os.WriteFile(filepath.Join(dir, cbomName), []byte(cbomBody), 0o644); err != nil {
		t.Fatal(err)
	}

	arts := findArtifacts(dir)
	srv := httptest.NewServer(newServeMux("/dev/null", "/dev/null", arts))
	defer srv.Close()

	// Manifest must be a one-element array describing the CBOM at its route.
	manifest := httpGet(t, srv.URL+"/artifacts/manifest.json")
	for _, want := range []string{`"kind":"cbom"`, `"route":"/artifacts/cbom.json"`, `"filename":"` + cbomName + `"`} {
		if !strings.Contains(manifest, want) {
			t.Errorf("manifest %q missing %q", manifest, want)
		}
	}
	if strings.Count(manifest, `"kind"`) != 1 {
		t.Errorf("manifest should list only the 1 on-disk artifact: %q", manifest)
	}

	// The artifact route serves the body + an attachment disposition naming the
	// real timestamped file.
	resp, err := http.Get(srv.URL + "/artifacts/cbom.json")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("artifact route status = %d, want 200", resp.StatusCode)
	}
	if cd := resp.Header.Get("Content-Disposition"); !strings.Contains(cd, "attachment") || !strings.Contains(cd, cbomName) {
		t.Errorf("Content-Disposition = %q, want attachment with %q", cd, cbomName)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != cbomBody {
		t.Errorf("artifact body = %q, want %q", body, cbomBody)
	}
}

// TestLoopbackHostGuard verifies the DNS-rebinding defense: loopback Host values
// (with or without the bound port) are served, while any foreign Host (a rebound
// DNS name pointed at 127.0.0.1) is rejected with 403 — an allowlist, not a
// denylist.
func TestLoopbackHostGuard(t *testing.T) {
	const port = 8675
	guard := loopbackHostGuard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), port)

	allowed := []string{
		"localhost",
		"localhost:8675",
		"127.0.0.1",
		"127.0.0.1:8675",
		"[::1]",
		"[::1]:8675",
	}
	for _, host := range allowed {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Host = host
		rec := httptest.NewRecorder()
		guard.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("Host %q = %d, want 200 (loopback must be allowed)", host, rec.Code)
		}
	}

	rejected := []string{
		"evil.com",
		"evil.com:8675",
		"attacker.example",
		"127.0.0.1:9999", // wrong port
		"localhost:9999", // wrong port
		"",
	}
	for _, host := range rejected {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Host = host
		rec := httptest.NewRecorder()
		guard.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("Host %q = %d, want 403 (non-loopback must be rejected)", host, rec.Code)
		}
	}
}

func httpGet(t *testing.T, url string) string {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s status = %d, want 200", url, resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}
