package regularrp

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	api "github.com/catalystcommunity/linkkeys/sdks/regular-rp/go/generated"
)

// Unit tests for CachedResolver: cache bounds/eviction, boundary isolation
// between distinct instances, stale-never-presented-as-fresh, and
// singleflight coalescing of concurrent refreshes. These do not touch a
// real network — a fake api.Transport stands in for the RP.

// buildSignedResponse builds a valid RpResolveApplicationKeysResponse for
// one instance: one usable Ed25519 signing key, attested and signed by a
// freshly generated domain signing key, with a far-future key/attestation
// lifetime so cache-behavior tests (which move the simulated clock by
// minutes, not days) never accidentally cross a classification boundary —
// that boundary is already covered by TestConformanceAttestation and
// TestConformanceRevocation.
func buildSignedResponse(t *testing.T, instance InstanceRef, keyID string, now time.Time) api.RpResolveApplicationKeysResponse {
	t.Helper()

	domainPub, domainPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate domain key: %v", err)
	}
	appPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate app key: %v", err)
	}

	domainKey := api.DomainPublicKey{
		KeyId:       "domain-key-1",
		PublicKey:   domainPub,
		Fingerprint: Fingerprint(domainPub),
		Algorithm:   "ed25519",
		KeyUsage:    "sign",
		CreatedAt:   now.Add(-24 * time.Hour).Format(time.RFC3339),
		ExpiresAt:   now.Add(10 * 365 * 24 * time.Hour).Format(time.RFC3339),
	}

	attestation := api.ApplicationKeyAttestation{
		SubjectUserId:        instance.SubjectUserID,
		SubjectDomain:        instance.SubjectDomain,
		ApplicationId:        instance.ApplicationID,
		InstanceId:           instance.InstanceID,
		KeyId:                keyID,
		KeyUsage:             KeyUsageSign,
		Algorithm:            "ed25519",
		PublicKey:            appPub,
		Fingerprint:          Fingerprint(appPub),
		KeyCreatedAt:         now.Add(-time.Hour).Format(time.RFC3339),
		KeyExpiresAt:         now.Add(365 * 24 * time.Hour).Format(time.RFC3339),
		AttestedAt:           now.Format(time.RFC3339),
		AttestationExpiresAt: now.Add(24 * time.Hour).Format(time.RFC3339),
	}
	attestationBytes := api.EncodeApplicationKeyAttestation(attestation)
	sig := ed25519.Sign(domainPriv, AttestationSignatureInput(attestationBytes))

	return api.RpResolveApplicationKeysResponse{
		SubjectUserId: instance.SubjectUserID,
		SubjectDomain: instance.SubjectDomain,
		ApplicationId: instance.ApplicationID,
		InstanceId:    instance.InstanceID,
		ApplicationKeys: []api.SignedApplicationKeyAttestation{{
			Attestation: attestationBytes,
			Signatures: []api.ClaimSignature{{
				Domain:        instance.SubjectDomain,
				SignedByKeyId: domainKey.KeyId,
				Signature:     sig,
			}},
		}},
		ApplicationKeyRevocations: nil,
		HomeDomainKeys:            []api.DomainPublicKey{domainKey},
		HomeDomainKeyRevocations:  nil,
		FetchedAt:                 now.Format(time.RFC3339),
		RevocationsCheckedAt:      now.Format(time.RFC3339),
		CacheStatus:               "refreshed",
	}
}

// fakeTransport serves a fixed, per-instance canned response for
// `Rp/resolve-application-keys`, counting calls and optionally failing.
type fakeTransport struct {
	mu        sync.Mutex
	calls     int
	fail      bool
	responses map[InstanceRef]api.RpResolveApplicationKeysResponse
}

func newFakeTransport() *fakeTransport {
	return &fakeTransport{responses: make(map[InstanceRef]api.RpResolveApplicationKeysResponse)}
}

func (f *fakeTransport) set(instance InstanceRef, resp api.RpResolveApplicationKeysResponse) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.responses[instance] = resp
}

func (f *fakeTransport) setFail(fail bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fail = fail
}

func (f *fakeTransport) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *fakeTransport) Call(_ context.Context, service, op string, payload []byte) ([]byte, error) {
	f.mu.Lock()
	f.calls++
	fail := f.fail
	f.mu.Unlock()

	if service != "Rp" || op != "resolve-application-keys" {
		return nil, fmt.Errorf("unexpected call %s/%s", service, op)
	}
	if fail {
		return nil, errors.New("simulated RP failure")
	}
	req, err := api.DecodeRpResolveApplicationKeysRequest(payload)
	if err != nil {
		return nil, err
	}
	key := InstanceRef{SubjectUserID: req.SubjectUserId, SubjectDomain: req.SubjectDomain, ApplicationID: req.ApplicationId, InstanceID: req.InstanceId}
	f.mu.Lock()
	resp, ok := f.responses[key]
	f.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("fake transport: no canned response for %+v", key)
	}
	return api.EncodeRpResolveApplicationKeysResponse(resp), nil
}

func mustUsableKey(t *testing.T, keys VerifiedApplicationKeySet, keyID string) {
	t.Helper()
	if _, err := keys.KeyForUse(keyID, KeyUsageSign, "ed25519"); err != nil {
		t.Errorf("expected key %s to be usable: %v", keyID, err)
	}
}

func instanceA() InstanceRef {
	return InstanceRef{SubjectUserID: "018f0000-0000-7000-8000-000000000001", SubjectDomain: "app-conformance.example", ApplicationID: "tinku", InstanceID: "instance-a"}
}

// TestCacheFreshRefreshedStale exercises the three Freshness states across
// one instance: an uncached Resolve fetches (Refreshed), a second Resolve
// inside the TTL is served locally (Fresh, no new RP call), and once the RP
// starts failing, a Resolve past TTL falls back to the last verified
// material (Stale) rather than erroring or silently looking fresh.
func TestCacheFreshRefreshedStale(t *testing.T) {
	instance := instanceA()
	clock := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	transport := newFakeTransport()
	transport.set(instance, buildSignedResponse(t, instance, "app-key-1", clock))

	r := NewCachedResolver(transport, CachedResolverOptions{
		TTL: time.Minute,
		Now: func() time.Time { return clock },
	})

	res1, err := r.Resolve(context.Background(), instance, nil)
	if err != nil {
		t.Fatalf("first resolve: %v", err)
	}
	if res1.Freshness != FreshnessRefreshed {
		t.Errorf("first resolve: want FreshnessRefreshed, got %s", res1.Freshness)
	}
	mustUsableKey(t, res1.Keys, "app-key-1")
	if got := transport.callCount(); got != 1 {
		t.Fatalf("want 1 RP call after first resolve, got %d", got)
	}

	// Still within TTL: served from cache, no new RP call.
	res2, err := r.Resolve(context.Background(), instance, nil)
	if err != nil {
		t.Fatalf("second resolve: %v", err)
	}
	if res2.Freshness != FreshnessFresh {
		t.Errorf("second resolve: want FreshnessFresh, got %s", res2.Freshness)
	}
	if got := transport.callCount(); got != 1 {
		t.Fatalf("want still 1 RP call after fresh-cache resolve, got %d", got)
	}

	// Advance past TTL with the RP still healthy: a third resolve
	// refreshes again.
	clock = clock.Add(2 * time.Minute)
	res3, err := r.Resolve(context.Background(), instance, nil)
	if err != nil {
		t.Fatalf("third resolve: %v", err)
	}
	if res3.Freshness != FreshnessRefreshed {
		t.Errorf("third resolve: want FreshnessRefreshed, got %s", res3.Freshness)
	}
	if got := transport.callCount(); got != 2 {
		t.Fatalf("want 2 RP calls after third resolve, got %d", got)
	}

	// Advance past TTL again, but now the RP is unreachable: fall back
	// to the last verified material, marked stale — never silently fresh.
	transport.setFail(true)
	clock = clock.Add(2 * time.Minute)
	res4, err := r.Resolve(context.Background(), instance, nil)
	if err != nil {
		t.Fatalf("fourth resolve should fall back to stale, not error: %v", err)
	}
	if res4.Freshness != FreshnessStale {
		t.Errorf("fourth resolve: want FreshnessStale, got %s", res4.Freshness)
	}
	mustUsableKey(t, res4.Keys, "app-key-1")
}

// TestCacheNoStaleWithoutPriorFetch confirms an RP failure with nothing yet
// cached is a hard error, not a fabricated stale result.
func TestCacheNoStaleWithoutPriorFetch(t *testing.T) {
	instance := instanceA()
	transport := newFakeTransport()
	transport.setFail(true)
	r := NewCachedResolver(transport, CachedResolverOptions{})

	_, err := r.Resolve(context.Background(), instance, nil)
	if err == nil {
		t.Fatal("expected an error when the RP fails and nothing is cached")
	}
	var noCached *NoCachedResultError
	if !errors.As(err, &noCached) {
		t.Errorf("expected *NoCachedResultError, got %T: %v", err, err)
	}
}

// TestCacheBoundedEviction confirms the cache evicts the least-recently-used
// instance once MaxEntries is reached, rather than growing without bound.
func TestCacheBoundedEviction(t *testing.T) {
	clock := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	transport := newFakeTransport()
	instances := []InstanceRef{
		{SubjectUserID: "018f0000-0000-7000-8000-000000000001", SubjectDomain: "app-conformance.example", ApplicationID: "tinku", InstanceID: "instance-1"},
		{SubjectUserID: "018f0000-0000-7000-8000-000000000002", SubjectDomain: "app-conformance.example", ApplicationID: "tinku", InstanceID: "instance-2"},
		{SubjectUserID: "018f0000-0000-7000-8000-000000000003", SubjectDomain: "app-conformance.example", ApplicationID: "tinku", InstanceID: "instance-3"},
	}
	for i, inst := range instances {
		transport.set(inst, buildSignedResponse(t, inst, fmt.Sprintf("app-key-%d", i), clock))
	}

	r := NewCachedResolver(transport, CachedResolverOptions{
		MaxEntries: 2,
		TTL:        time.Hour,
		Now:        func() time.Time { return clock },
	})

	for _, inst := range instances[:2] {
		if _, err := r.Resolve(context.Background(), inst, nil); err != nil {
			t.Fatalf("resolve %+v: %v", inst, err)
		}
	}
	if got := r.Len(); got != 2 {
		t.Fatalf("want 2 cached entries, got %d", got)
	}

	// Resolving a third distinct instance must evict the least-recently
	// used one (instances[0], never touched again) rather than growing
	// past MaxEntries.
	if _, err := r.Resolve(context.Background(), instances[2], nil); err != nil {
		t.Fatalf("resolve instance 3: %v", err)
	}
	if got := r.Len(); got != 2 {
		t.Fatalf("want cache to stay bounded at 2 entries, got %d", got)
	}

	callsBefore := transport.callCount()
	// instances[0] was evicted: resolving it again must hit the RP, not
	// a stale cache entry that should no longer exist.
	if _, err := r.Resolve(context.Background(), instances[0], nil); err != nil {
		t.Fatalf("re-resolve evicted instance: %v", err)
	}
	if got := transport.callCount(); got != callsBefore+1 {
		t.Errorf("expected a fresh RP call for the evicted instance, call count %d -> %d", callsBefore, got)
	}
}

// TestCacheIsolatesDistinctInstances confirms the cache key is the full
// canonical InstanceRef tuple: two instances that differ in only ONE field
// (subject, domain, application, or instance id) must never share a cache
// entry or leak keys into each other's result.
func TestCacheIsolatesDistinctInstances(t *testing.T) {
	base := instanceA()
	clock := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	variants := []struct {
		name string
		ref  InstanceRef
	}{
		{"base", base},
		{"different subject", InstanceRef{SubjectUserID: "018f0000-0000-7000-8000-000000000099", SubjectDomain: base.SubjectDomain, ApplicationID: base.ApplicationID, InstanceID: base.InstanceID}},
		{"different domain", InstanceRef{SubjectUserID: base.SubjectUserID, SubjectDomain: "other.example", ApplicationID: base.ApplicationID, InstanceID: base.InstanceID}},
		{"different application", InstanceRef{SubjectUserID: base.SubjectUserID, SubjectDomain: base.SubjectDomain, ApplicationID: "other-app", InstanceID: base.InstanceID}},
		{"different instance", InstanceRef{SubjectUserID: base.SubjectUserID, SubjectDomain: base.SubjectDomain, ApplicationID: base.ApplicationID, InstanceID: "instance-b"}},
	}

	transport := newFakeTransport()
	for i, v := range variants {
		transport.set(v.ref, buildSignedResponse(t, v.ref, fmt.Sprintf("key-%d", i), clock))
	}
	r := NewCachedResolver(transport, CachedResolverOptions{TTL: time.Hour, Now: func() time.Time { return clock }})

	for i, v := range variants {
		res, err := r.Resolve(context.Background(), v.ref, nil)
		if err != nil {
			t.Fatalf("%s: resolve: %v", v.name, err)
		}
		wantKeyID := fmt.Sprintf("key-%d", i)
		mustUsableKey(t, res.Keys, wantKeyID)
		for j, other := range variants {
			if j == i {
				continue
			}
			otherKeyID := fmt.Sprintf("key-%d", j)
			if _, err := res.Keys.KeyForUse(otherKeyID, KeyUsageSign, "ed25519"); err == nil {
				t.Errorf("%s: unexpectedly saw %s's key %s in its own result", v.name, other.name, otherKeyID)
			}
		}
	}
	if got := r.Len(); got != len(variants) {
		t.Fatalf("want %d distinct cache entries, got %d", len(variants), got)
	}
}

// TestCacheCoalescesConcurrentRefreshes confirms N concurrent Resolve calls
// for the SAME uncached instance produce exactly one underlying RP call.
func TestCacheCoalescesConcurrentRefreshes(t *testing.T) {
	instance := instanceA()
	clock := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	release := make(chan struct{})
	var calls int32
	blocking := blockingCallFunc(func() ([]byte, error) {
		atomic.AddInt32(&calls, 1)
		<-release
		resp := buildSignedResponse(t, instance, "app-key-1", clock)
		return api.EncodeRpResolveApplicationKeysResponse(resp), nil
	})

	r := NewCachedResolver(blocking, CachedResolverOptions{Now: func() time.Time { return clock }})

	const n = 8
	var wg sync.WaitGroup
	results := make([]ResolveResult, n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = r.Resolve(context.Background(), instance, nil)
		}(i)
	}

	// Give every goroutine a chance to reach the blocking call before
	// releasing it.
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()

	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("want exactly 1 underlying RP call for %d concurrent resolves, got %d", n, got)
	}
	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Errorf("resolve %d: %v", i, errs[i])
			continue
		}
		if results[i].Freshness != FreshnessRefreshed {
			t.Errorf("resolve %d: want FreshnessRefreshed, got %s", i, results[i].Freshness)
		}
		mustUsableKey(t, results[i].Keys, "app-key-1")
	}
}

// blockingCallFunc adapts a func to api.Transport for
// TestCacheCoalescesConcurrentRefreshes.
type blockingCallFunc func() ([]byte, error)

func (f blockingCallFunc) Call(_ context.Context, _, _ string, _ []byte) ([]byte, error) {
	return f()
}
