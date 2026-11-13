package api

import (
	_ "embed"
	"net/http"
	"os"
	"path/filepath"

	"github.com/gin-gonic/gin"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/managementasset"
)

const (
	dashboardFileName         = "dashboard.html"
	dashboardSettingsFileName = "dashboard.json"
)

// dashboardHTML is the built-in read-only dashboard: accounts, their quota windows,
// which account receives new sessions, and recent requests. The page holds no data
// itself; it reads the Management API with the management key the viewer enters.
//
//go:embed dashboard.html
var dashboardHTML []byte

func (s *Server) dashboardEnabled() bool {
	cfg := s.getConfig()
	return cfg != nil && !cfg.Home.Enabled && !cfg.RemoteManagement.DisableControlPanel
}

// dashboardStaticFile returns the path of name in the management static directory when
// that file exists.
func (s *Server) dashboardStaticFile(name string) (string, bool) {
	dir := managementasset.StaticDir(s.configFilePath)
	if dir == "" {
		return "", false
	}
	path := filepath.Join(dir, name)
	info, errStat := os.Stat(path)
	if errStat != nil || info.IsDir() {
		return "", false
	}
	return path, true
}

// serveDashboard serves the dashboard page. A dashboard.html next to management.html
// replaces the built-in page.
func (s *Server) serveDashboard(c *gin.Context) {
	if !s.dashboardEnabled() {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}
	if path, ok := s.dashboardStaticFile(dashboardFileName); ok {
		c.File(path)
		return
	}
	c.Data(http.StatusOK, "text/html; charset=utf-8", dashboardHTML)
}

// serveDashboardSettings serves the optional dashboard.json next to management.html.
// It carries display settings only, such as names for client addresses.
func (s *Server) serveDashboardSettings(c *gin.Context) {
	if !s.dashboardEnabled() {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}
	path, ok := s.dashboardStaticFile(dashboardSettingsFileName)
	if !ok {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}
	c.File(path)
}
