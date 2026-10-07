package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"testing"
)

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"0.9.11", "0.9.10", 1}, {"v0.9.11", "0.9.11", 0}, {"0.10.0", "0.9.99", 1},
		{"1.0.0", "0.9.10", 1}, {"0.9.9", "0.9.10", -1}, {"dev", "0.0.1", -1},
	}
	for _, c := range cases {
		if got := CompareVersions(c.a, c.b); got != c.want {
			t.Errorf("Compare(%q,%q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestAssetName(t *testing.T) {
	if AssetName("darwin", "arm64", "0.9.11") != "PrivacyLens-0.9.11.pkg" ||
		AssetName("windows", "amd64", "0.9.11") != "PrivacyLens-Setup-0.9.11.exe" ||
		AssetName("linux", "arm", "0.9.11") != "PrivacyLens-0.9.11-linux-armv7.tar.gz" ||
		AssetName("linux", "amd64", "0.9.11") != "PrivacyLens-0.9.11-linux-amd64.tar.gz" {
		t.Error("asset names do not match build-all.sh output")
	}
}

// fakeGitHub serves a release whose installer for this platform is body,
// with a SHA256SUMS.txt that may be correct, wrong, or absent.
func fakeGitHub(t *testing.T, version, body string, sums string) *httptest.Server {
	t.Helper()
	name := AssetName(runtime.GOOS, runtime.GOARCH, version)
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/acme/pl/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") == "" {
			t.Error("GitHub requires a User-Agent")
		}
		assets := fmt.Sprintf(`{"name":%q,"size":%d,"browser_download_url":%q}`, name, len(body), srv.URL+"/dl/"+name)
		if sums != "" {
			assets += fmt.Sprintf(`,{"name":"SHA256SUMS.txt","size":%d,"browser_download_url":%q}`, len(sums), srv.URL+"/dl/SHA256SUMS.txt")
		}
		fmt.Fprintf(w, `{"tag_name":"v%s","body":"Fixes things","html_url":"https://example/rel","published_at":"2026-10-08T10:00:00Z","assets":[%s]}`, version, assets)
	})
	mux.HandleFunc("/dl/"+name, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) })
	mux.HandleFunc("/dl/SHA256SUMS.txt", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, sums) })
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func sumOf(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func TestCheckAndDownloadVerifies(t *testing.T) {
	body := "fake installer bytes"
	name := AssetName(runtime.GOOS, runtime.GOARCH, "0.9.11")
	srv := fakeGitHub(t, "0.9.11", body, sumOf(body)+"  "+name+"\n"+sumOf("other")+"  other.zip\n")
	saved := APIBase
	APIBase = srv.URL
	t.Cleanup(func() { APIBase = saved })

	rel, newer, err := Check(context.Background(), "acme/pl", "0.9.10")
	if err != nil || !newer || rel.Version != "0.9.11" || rel.Asset.Name != name || rel.SumsURL == "" || rel.Notes != "Fixes things" {
		t.Fatalf("Check = %+v newer=%v err=%v", rel, newer, err)
	}
	if _, newer, err = Check(context.Background(), "acme/pl", "0.9.11"); err != nil || newer {
		t.Errorf("same version must not be newer: newer=%v err=%v", newer, err)
	}
	var last int64
	path, err := Download(context.Background(), rel, t.TempDir(), func(done, total int64) { last = done })
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path); string(b) != body || last != int64(len(body)) {
		t.Errorf("downloaded %q progress %d", b, last)
	}
}

func TestDownloadRejectsBadOrMissingChecksum(t *testing.T) {
	body := "fake installer bytes"
	name := AssetName(runtime.GOOS, runtime.GOARCH, "0.9.11")
	saved := APIBase
	t.Cleanup(func() { APIBase = saved })

	APIBase = fakeGitHub(t, "0.9.11", body, sumOf("tampered")+"  "+name+"\n").URL
	rel, _, err := Check(context.Background(), "acme/pl", "0.9.10")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if _, err := Download(context.Background(), rel, dir, nil); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Errorf("mismatched checksum must fail: %v", err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Error("rejected download must be removed")
	}

	APIBase = fakeGitHub(t, "0.9.11", body, "").URL
	rel, _, err = Check(context.Background(), "acme/pl", "0.9.10")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Download(context.Background(), rel, dir, nil); err == nil || !strings.Contains(err.Error(), SumsFile) {
		t.Errorf("missing SHA256SUMS.txt must fail: %v", err)
	}
}

func TestCheckNoReleases(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(srv.Close)
	saved := APIBase
	APIBase = srv.URL
	t.Cleanup(func() { APIBase = saved })
	if _, _, err := Check(context.Background(), "acme/pl", "0.9.10"); err == nil || !strings.Contains(err.Error(), "public") {
		t.Errorf("404 should explain the repo must be public with a release: %v", err)
	}
}
