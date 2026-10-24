//go:build conformance

package main

import (
	"os"
	"testing"

	acmetest "github.com/cert-manager/cert-manager/test/acme"

	"github.com/captainmack/porkbun-arm64-webhook/porkbun"
)

var (
	zone = os.Getenv("TEST_ZONE_NAME")
)

// TestRunsSuite is cert-manager's DNS01 conformance suite. It needs a real
// Porkbun zone, real API keys in testdata/porkbun-solver and control-plane
// binaries (make test), so it is behind the `conformance` build tag (make test).
func TestRunsSuite(t *testing.T) {
	if zone == "" {
		t.Fatal("TEST_ZONE_NAME must be set, e.g. TEST_ZONE_NAME=example.com.")
	}
	// The manifest path should contain a file named config.json that is a
	// snippet of valid configuration that should be included on the
	// ChallengeRequest passed as part of the test cases.

	fixture := acmetest.NewFixture(porkbun.New(),
		acmetest.SetStrict(true),
		acmetest.SetResolvedZone(zone),
		acmetest.SetAllowAmbientCredentials(false),
		acmetest.SetManifestPath("testdata/porkbun-solver"),
	)
	//need to uncomment and  RunConformance delete runBasic and runExtended once https://github.com/cert-manager/cert-manager/pull/4835 is merged
	//fixture.RunConformance(t)
	fixture.RunBasic(t)
	fixture.RunExtended(t)

}
