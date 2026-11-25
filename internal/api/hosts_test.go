package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"nfmonitor/internal/priv"
	"nfmonitor/internal/remote"
)

func newTestServer(t *testing.T) (*Server, http.Handler) {
	st, err := remote.OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{Priv: priv.NewClient(), Version: "test", Hosts: remote.NewManager(st)}
	t.Cleanup(s.Hosts.Close)
	return s, s.Handler()
}

func call(h http.Handler, method, path, body string, hdr bool) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if hdr {
		req.Header.Set("X-Nfmonitor", "1")
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestHostsAPI(t *testing.T) {
	_, h := newTestServer(t)

	// 没有自定义头：拒绝（跨站防护）
	if rec := call(h, "POST", "/api/hosts/save", `{"addr":"10.0.0.2","user":"ops","auth":"password","secrets":{"password":"pw-123"}}`, false); rec.Code != http.StatusForbidden {
		t.Fatalf("no header: %d", rec.Code)
	}
	rec := call(h, "POST", "/api/hosts/save", `{"addr":"10.0.0.2","user":"ops","auth":"password","secrets":{"password":"pw-123"}}`, true)
	if rec.Code != 200 {
		t.Fatalf("save: %d %s", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), "pw-123") {
		t.Fatal("secret echoed back")
	}
	var saved remote.HostView
	json.Unmarshal(rec.Body.Bytes(), &saved)
	if saved.ID == "" || !saved.HasPassword || saved.Port != 22 {
		t.Fatalf("saved: %+v", saved)
	}

	rec = call(h, "GET", "/api/hosts", "", false)
	if rec.Code != 200 || strings.Contains(rec.Body.String(), "pw-123") || !strings.Contains(rec.Body.String(), saved.ID) {
		t.Fatalf("list: %d %s", rec.Code, rec.Body)
	}

	// 改名不带口令：口令沿用
	rec = call(h, "POST", "/api/hosts/save", `{"id":"`+saved.ID+`","name":"db","addr":"10.0.0.2","user":"ops","auth":"password"}`, true)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"hasPassword":true`) {
		t.Fatalf("rename: %d %s", rec.Code, rec.Body)
	}

	// 没确认主机指纹：采集接口给出提示而不是连接
	rec = call(h, "GET", "/api/links?host="+saved.ID, "", false)
	if rec.Code != 500 || !strings.Contains(rec.Body.String(), "指纹") {
		t.Errorf("links without host key: %d %s", rec.Code, rec.Body)
	}
	rec = call(h, "GET", "/api/meta?host="+saved.ID, "", false)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"remote":true`) {
		t.Errorf("meta: %d %s", rec.Code, rec.Body)
	}
	// 远程主机不走本机提权
	rec = call(h, "POST", "/api/elevate?host="+saved.ID, "", true)
	if rec.Code != 500 {
		t.Errorf("elevate remote: %d %s", rec.Code, rec.Body)
	}

	rec = call(h, "POST", "/api/hosts/delete", `{"id":"`+saved.ID+`"}`, true)
	if rec.Code != 200 {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body)
	}
	rec = call(h, "GET", "/api/links?host="+saved.ID, "", false)
	if rec.Code != 500 || !strings.Contains(rec.Body.String(), "主机不存在") {
		t.Errorf("deleted host: %d %s", rec.Code, rec.Body)
	}
	// 校验失败
	rec = call(h, "POST", "/api/hosts/save", `{"addr":"-oProxyCommand=sh","user":"ops","auth":"password","secrets":{"password":"x"}}`, true)
	if rec.Code != 500 {
		t.Errorf("bad addr accepted: %d", rec.Code)
	}
}

func TestHostsUnavailable(t *testing.T) {
	s := &Server{Priv: priv.NewClient(), Version: "test"}
	h := s.Handler()
	rec := call(h, "GET", "/api/links?host=abcdefabcdef", "", false)
	if rec.Code != 500 || !strings.Contains(rec.Body.String(), "远程主机配置不可用") {
		t.Errorf("%d %s", rec.Code, rec.Body)
	}
	rec = call(h, "GET", "/api/hosts", "", false)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"hosts":[]`) {
		t.Errorf("%d %s", rec.Code, rec.Body)
	}
}
