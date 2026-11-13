package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	proxyconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
)

func getDashboardPath(t *testing.T, server *Server, path string) *httptest.ResponseRecorder {
	t.Helper()
	rr := httptest.NewRecorder()
	server.engine.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
	return rr
}

func TestDashboardServesBuiltInPage(t *testing.T) {
	t.Setenv("MANAGEMENT_STATIC_PATH", t.TempDir())
	server := newTestServer(t)

	rr := getDashboardPath(t, server, "/dashboard.html")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	if contentType := rr.Header().Get("Content-Type"); !strings.HasPrefix(contentType, "text/html") {
		t.Fatalf("Content-Type = %q, want text/html", contentType)
	}
	if !strings.Contains(rr.Body.String(), "<title>Hub dashboard</title>") {
		t.Fatal("body is not the built-in dashboard page")
	}

	if rr = getDashboardPath(t, server, "/dashboard.json"); rr.Code != http.StatusNotFound {
		t.Fatalf("dashboard.json status without a settings file = %d, want %d", rr.Code, http.StatusNotFound)
	}
}

func TestDashboardServesFilesFromStaticDirectory(t *testing.T) {
	staticDir := t.TempDir()
	t.Setenv("MANAGEMENT_STATIC_PATH", staticDir)
	server := newTestServer(t)
	for name, content := range map[string]string{
		"dashboard.html": "<html>custom dashboard</html>",
		"dashboard.json": `{"clients":{"192.0.2.1":"laptop"}}`,
	} {
		if errWrite := os.WriteFile(filepath.Join(staticDir, name), []byte(content), 0o600); errWrite != nil {
			t.Fatalf("write %s: %v", name, errWrite)
		}
	}

	if rr := getDashboardPath(t, server, "/dashboard.html"); rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "custom dashboard") {
		t.Fatalf("dashboard.html = %d %q, want the page from the static directory", rr.Code, rr.Body.String())
	}
	if rr := getDashboardPath(t, server, "/dashboard.json"); rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "laptop") {
		t.Fatalf("dashboard.json = %d %q, want the settings file", rr.Code, rr.Body.String())
	}
}

func TestDashboardDisabledWithControlPanel(t *testing.T) {
	t.Setenv("MANAGEMENT_STATIC_PATH", t.TempDir())
	cfg := &proxyconfig.Config{}
	cfg.RemoteManagement.DisableControlPanel = true
	server := newTestServerWithConfig(t, cfg)

	for _, path := range []string{"/dashboard.html", "/dashboard.json"} {
		if rr := getDashboardPath(t, server, path); rr.Code != http.StatusNotFound {
			t.Fatalf("%s status = %d, want %d", path, rr.Code, http.StatusNotFound)
		}
	}
}
