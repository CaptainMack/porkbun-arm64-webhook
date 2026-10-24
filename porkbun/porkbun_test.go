package porkbun

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"

	acme "github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

const (
	testAPIKey    = "pk1_test"
	testSecretKey = "sk1_test"
	testNamespace = "cert-manager"
)

type record struct {
	ID, Name, Type, Content, TTL string
}

// fakePorkbun implements the slice of the Porkbun v3 JSON API the solver uses.
type fakePorkbun struct {
	mu      sync.Mutex
	nextID  int64
	records map[string][]record // domain -> records (Name is the full name, as Porkbun returns it)
	calls   []string
}

func newFakePorkbun(t *testing.T) (*fakePorkbun, *url.URL) {
	t.Helper()
	f := &fakePorkbun{nextID: 1000, records: map[string][]record{}}
	srv := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL + "/api/json/v3/")
	return f, u
}

func (f *fakePorkbun) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()

	var body map[string]any
	_ = json.NewDecoder(r.Body).Decode(&body)
	reply := func(code int, v any) { w.WriteHeader(code); _ = json.NewEncoder(w).Encode(v) }
	if r.Method != http.MethodPost || body["apikey"] != testAPIKey || body["secretapikey"] != testSecretKey {
		reply(http.StatusBadRequest, map[string]string{"status": "ERROR", "message": "Invalid API key."})
		return
	}

	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/json/v3/dns/"), "/")
	op, domain := parts[0], parts[1]
	f.calls = append(f.calls, op)
	switch op {
	case "retrieve":
		recs := []map[string]string{}
		for _, rec := range f.records[domain] {
			recs = append(recs, map[string]string{"id": rec.ID, "name": rec.Name, "type": rec.Type, "content": rec.Content, "ttl": rec.TTL})
		}
		reply(http.StatusOK, map[string]any{"status": "SUCCESS", "records": recs})
	case "create":
		name := domain
		if sub, _ := body["name"].(string); sub != "" {
			name = sub + "." + domain
		}
		f.nextID++
		id := strconv.FormatInt(f.nextID, 10)
		f.records[domain] = append(f.records[domain], record{ID: id, Name: name, Type: body["type"].(string), Content: body["content"].(string), TTL: body["ttl"].(string)})
		reply(http.StatusOK, map[string]any{"status": "SUCCESS", "id": f.nextID})
	case "delete":
		kept := f.records[domain][:0]
		for _, rec := range f.records[domain] {
			if rec.ID != parts[2] {
				kept = append(kept, rec)
			}
		}
		f.records[domain] = kept
		reply(http.StatusOK, map[string]string{"status": "SUCCESS"})
	default:
		reply(http.StatusNotFound, map[string]string{"status": "ERROR", "message": "unknown endpoint"})
	}
}

func (f *fakePorkbun) seed(domain string, recs ...record) {
	f.records[domain] = append(f.records[domain], recs...)
}

func newSolver(t *testing.T, base *url.URL, secretData map[string][]byte) *PorkbunSolver {
	t.Helper()
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "porkbun-credentials", Namespace: testNamespace},
		Data:       secretData,
	}
	return &PorkbunSolver{kube: fake.NewSimpleClientset(secret), baseURL: base}
}

func validSecret() map[string][]byte {
	return map[string][]byte{"api-key": []byte(testAPIKey), "secret-key": []byte(testSecretKey)}
}

func challenge(fqdn, zone, key string) *acme.ChallengeRequest {
	cfg, _ := json.Marshal(map[string]any{
		"apiKeySecretRef":    map[string]string{"name": "porkbun-credentials", "key": "api-key"},
		"secretKeySecretRef": map[string]string{"name": "porkbun-credentials", "key": "secret-key"},
	})
	return &acme.ChallengeRequest{
		ResolvedFQDN:      fqdn,
		ResolvedZone:      zone,
		Key:               key,
		ResourceNamespace: testNamespace,
		Config:            &apiextensionsv1.JSON{Raw: cfg},
	}
}

func TestPresentCreatesTXTRecordWithMinimumTTL(t *testing.T) {
	api, base := newFakePorkbun(t)
	s := newSolver(t, base, validSecret())

	if err := s.Present(challenge("_acme-challenge.preview.example.com.", "example.com.", "token-1")); err != nil {
		t.Fatalf("Present: %v", err)
	}

	recs := api.records["example.com"]
	if len(recs) != 1 {
		t.Fatalf("want 1 record, got %d: %+v", len(recs), recs)
	}
	got := recs[0]
	if got.Name != "_acme-challenge.preview.example.com" || got.Type != "TXT" || got.Content != "token-1" {
		t.Errorf("unexpected record %+v", got)
	}
	if got.TTL != "300" {
		t.Errorf("TTL = %q, want Porkbun's 300s minimum", got.TTL)
	}
}

func TestPresentAtZoneApex(t *testing.T) {
	api, base := newFakePorkbun(t)
	s := newSolver(t, base, validSecret())

	if err := s.Present(challenge("_acme-challenge.example.com.", "example.com.", "apex")); err != nil {
		t.Fatalf("Present: %v", err)
	}
	if name := api.records["example.com"][0].Name; name != "_acme-challenge.example.com" {
		t.Errorf("record name = %q", name)
	}
}

func TestPresentIsIdempotent(t *testing.T) {
	api, base := newFakePorkbun(t)
	s := newSolver(t, base, validSecret())
	ch := challenge("_acme-challenge.example.com.", "example.com.", "token-1")

	for i := 0; i < 2; i++ {
		if err := s.Present(ch); err != nil {
			t.Fatalf("Present #%d: %v", i+1, err)
		}
	}
	if n := len(api.records["example.com"]); n != 1 {
		t.Errorf("want 1 record after presenting twice, got %d", n)
	}
}

func TestPresentKeepsSiblingTokens(t *testing.T) {
	// A wildcard and its apex share one _acme-challenge name with different tokens.
	api, base := newFakePorkbun(t)
	s := newSolver(t, base, validSecret())

	for _, key := range []string{"apex-token", "wildcard-token"} {
		if err := s.Present(challenge("_acme-challenge.example.com.", "example.com.", key)); err != nil {
			t.Fatalf("Present %s: %v", key, err)
		}
	}
	if n := len(api.records["example.com"]); n != 2 {
		t.Errorf("want 2 TXT records, got %d", n)
	}
}

func TestCleanUpDeletesOnlyTheMatchingRecord(t *testing.T) {
	api, base := newFakePorkbun(t)
	api.seed("example.com",
		record{ID: "1", Name: "_acme-challenge.example.com", Type: "TXT", Content: "token-1", TTL: "300"},
		record{ID: "2", Name: "_acme-challenge.example.com", Type: "TXT", Content: "other-token", TTL: "300"},
		record{ID: "3", Name: "example.com", Type: "TXT", Content: "token-1", TTL: "300"},
		record{ID: "4", Name: "_acme-challenge.example.com", Type: "CNAME", Content: "token-1", TTL: "300"},
	)
	s := newSolver(t, base, validSecret())

	if err := s.CleanUp(challenge("_acme-challenge.example.com.", "example.com.", "token-1")); err != nil {
		t.Fatalf("CleanUp: %v", err)
	}

	var ids []string
	for _, r := range api.records["example.com"] {
		ids = append(ids, r.ID)
	}
	if strings.Join(ids, ",") != "2,3,4" {
		t.Errorf("remaining records = %v, want only record 1 deleted", ids)
	}
}

func TestCleanUpHandlesIDsBeyondInt32(t *testing.T) {
	api, base := newFakePorkbun(t)
	api.seed("example.com", record{ID: "5000000000", Name: "_acme-challenge.example.com", Type: "TXT", Content: "big", TTL: "300"})
	s := newSolver(t, base, validSecret())

	if err := s.CleanUp(challenge("_acme-challenge.example.com.", "example.com.", "big")); err != nil {
		t.Fatalf("CleanUp: %v", err)
	}
	if n := len(api.records["example.com"]); n != 0 {
		t.Errorf("record with ID > 2^31 not deleted")
	}
}

func TestCleanUpWithoutRecordIsANoOp(t *testing.T) {
	_, base := newFakePorkbun(t)
	s := newSolver(t, base, validSecret())

	if err := s.CleanUp(challenge("_acme-challenge.example.com.", "example.com.", "gone")); err != nil {
		t.Errorf("CleanUp of a missing record should succeed, got %v", err)
	}
}

func TestRejectsNamesOutsideTheZone(t *testing.T) {
	api, base := newFakePorkbun(t)
	s := newSolver(t, base, validSecret())

	for _, ch := range []*acme.ChallengeRequest{
		challenge("_acme-challenge.evil.org.", "example.com.", "x"),
		challenge("_acme-challenge.notexample.com.", "example.com.", "x"),
		challenge("example.com.", "example.com.", "x"),
		challenge("_acme-challenge.example.com.", "", "x"),
	} {
		if err := s.Present(ch); err == nil {
			t.Errorf("Present(%q in %q) succeeded, want error", ch.ResolvedFQDN, ch.ResolvedZone)
		}
		if err := s.CleanUp(ch); err == nil {
			t.Errorf("CleanUp(%q in %q) succeeded, want error", ch.ResolvedFQDN, ch.ResolvedZone)
		}
	}
	if len(api.calls) != 0 {
		t.Errorf("rejected challenges still called the Porkbun API: %v", api.calls)
	}
}

func TestMissingSecretOrKeyFailsWithoutLeakingValues(t *testing.T) {
	_, base := newFakePorkbun(t)
	ch := challenge("_acme-challenge.example.com.", "example.com.", "x")

	noSecret := &PorkbunSolver{kube: fake.NewSimpleClientset(), baseURL: base}
	if err := noSecret.Present(ch); err == nil || !strings.Contains(err.Error(), "porkbun-credentials") {
		t.Errorf("missing secret: got %v", err)
	}

	missingKey := newSolver(t, base, map[string][]byte{"api-key": []byte(testAPIKey)})
	err := missingKey.Present(ch)
	if err == nil || !strings.Contains(err.Error(), `does not contain key "secret-key"`) {
		t.Errorf("missing key: got %v", err)
	}
	if err != nil && strings.Contains(err.Error(), testAPIKey) {
		t.Errorf("error leaks the API key: %v", err)
	}
}

func TestPorkbunAPIErrorsSurface(t *testing.T) {
	_, base := newFakePorkbun(t)
	s := newSolver(t, base, map[string][]byte{"api-key": []byte("pk1_wrong"), "secret-key": []byte("sk1_wrong")})

	err := s.Present(challenge("_acme-challenge.example.com.", "example.com.", "x"))
	if err == nil || !strings.Contains(err.Error(), "retrieve records error") {
		t.Errorf("want a retrieve error for bad credentials, got %v", err)
	}
}

func TestBadConfigIsRejected(t *testing.T) {
	_, base := newFakePorkbun(t)
	s := newSolver(t, base, validSecret())
	ch := challenge("_acme-challenge.example.com.", "example.com.", "x")
	ch.Config = &apiextensionsv1.JSON{Raw: []byte(`{not json`)}

	if err := s.Present(ch); err == nil || !strings.Contains(err.Error(), "config error") {
		t.Errorf("want config error, got %v", err)
	}
}
