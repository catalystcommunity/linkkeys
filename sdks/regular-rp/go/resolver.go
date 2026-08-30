package regularrp

import (
	"container/list"
	"context"
	"sync"
	"time"

	api "github.com/catalystcommunity/linkkeys/sdks/regular-rp/go/generated"
)

// The cached application-key resolver: asks the application's own RP
// (`Rp/resolve-application-keys`, API-key authenticated) for another
// instance's application keys, verifies the signed records ITSELF (the RP
// already validated before storing/returning them, per
// docs/application-keys.md's Caches section — this is the second,
// independent validation pass docs/application-keys.md's Caches section and
// csil/linkkeys.csil's RpResolveApplicationKeysResponse doc comment both
// call for: "The RP validates the material before it stores or returns it;
// the SDK validates it again before use"), and caches the result.
//
// Design points called out by the task this implements:
//
//   - The cache key is the canonical InstanceRef tuple (subject_user_id +
//     subject_domain + application_id + instance_id) — NEVER a handle. A
//     handle can move to a different account or be reused; a peer approval
//     must never silently transfer with it.
//   - The cache is BOUNDED (an LRU with a configurable entry cap), so a
//     misbehaving or malicious peer cannot grow this cache without bound by
//     asking about many distinct instances.
//   - Freshness is surfaced honestly as FreshnessFresh / FreshnessRefreshed
//     / FreshnessStale on every result — the same three-state vocabulary
//     the RP's own cache_status field already uses (csil/linkkeys.csil,
//     RpResolveApplicationKeysResponse), one layer up: this is the SDK's
//     OWN cache relative to the RP, not the RP's cache relative to the home
//     domain. A stale result is never returned as a bare key list that
//     loses the freshness alongside it — ResolveResult always carries both
//     together.
//   - Concurrent refreshes for the same instance are coalesced
//     (singleflight semantics, hand-rolled below rather than adding a
//     dependency for ~20 lines).

// Freshness describes how current a ResolveResult is, relative to THIS
// SDK's own cache (not the RP's).
type Freshness int

const (
	// FreshnessFresh: served from this SDK's local cache, within its TTL.
	// No RP call was made for this request.
	FreshnessFresh Freshness = iota
	// FreshnessRefreshed: this request itself fetched new signed material
	// from the RP and verified it.
	FreshnessRefreshed
	// FreshnessStale: the RP could not be reached (or returned an error)
	// for this request; the result is the last successfully verified
	// material. Never mistake this for current trust.
	FreshnessStale
)

func (f Freshness) String() string {
	switch f {
	case FreshnessFresh:
		return "fresh"
	case FreshnessRefreshed:
		return "refreshed"
	case FreshnessStale:
		return "stale"
	default:
		return "unknown"
	}
}

// ResolveResult is the outcome of one Resolve call: the verified key set,
// bound to how current it is. Freshness always travels WITH Keys — there is
// no accessor that returns Keys alone, so a caller cannot mistake a stale
// answer for a fresh one.
type ResolveResult struct {
	Keys      VerifiedApplicationKeySet
	Freshness Freshness
	FetchedAt time.Time
	// RPCacheStatus is the RP's OWN cache_status for the fetch that
	// produced the cached material ("fresh" / "refreshed" / "stale") —
	// informational only; this SDK's Freshness above is the value to act
	// on.
	RPCacheStatus string
}

// cacheEntry holds the raw, once-fetched signed material for one instance.
// Classification (usable / attestation-expired / key-expired / revoked)
// depends on `now`, so it is NOT cached — VerifyApplicationKeySet re-runs on
// every Resolve call, cheap for the handful of keys one instance holds.
type cacheEntry struct {
	instance InstanceRef

	applicationKeys           []api.SignedApplicationKeyAttestation
	applicationKeyRevocations []api.ApplicationKeyRevocation
	homeDomainKeys            []api.DomainPublicKey
	homeDomainKeyRevocations  []api.RevocationCertificate

	fetchedAt     time.Time
	rpCacheStatus string

	elem *list.Element // LRU position, valid only while r.mu is held
}

// CachedResolverOptions configures a CachedResolver.
type CachedResolverOptions struct {
	// MaxEntries bounds the cache: the least-recently-used instance is
	// evicted once this many distinct instances are cached. Defaults to
	// 1024.
	MaxEntries int
	// TTL is how long a cache entry is served without asking the RP
	// again. Defaults to 5 minutes — short enough to keep revocation
	// propagation reasonable without calling the RP on every message
	// verification.
	TTL time.Duration
	// SkewSeconds is the permitted clock skew passed to
	// VerifyApplicationKeySet's classification. Defaults to 300s,
	// matching APPLICATION_KEY_CLOCK_SKEW_SECONDS's server-side default
	// (docs/application-keys.md, Configuration).
	SkewSeconds int64
	// Now overrides the clock (tests only). Defaults to time.Now.
	Now func() time.Time
}

// CachedResolver resolves and caches application keys via an application's
// own RP.
type CachedResolver struct {
	client *api.RpClient
	opts   CachedResolverOptions

	mu      sync.Mutex
	entries map[InstanceRef]*cacheEntry
	order   *list.List // front = most recently used

	sf singleflightGroup
}

// NewCachedResolver builds a CachedResolver over transport (typically a
// *PinnedRpcTransport, but any api.Transport works — tests inject a fake).
func NewCachedResolver(transport api.Transport, opts CachedResolverOptions) *CachedResolver {
	if opts.MaxEntries <= 0 {
		opts.MaxEntries = 1024
	}
	if opts.TTL <= 0 {
		opts.TTL = 5 * time.Minute
	}
	if opts.SkewSeconds <= 0 {
		opts.SkewSeconds = 300
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &CachedResolver{
		client:  api.NewRpClient(transport),
		opts:    opts,
		entries: make(map[InstanceRef]*cacheEntry),
		order:   list.New(),
		sf:      newSingleflightGroup(),
	}
}

// Resolve returns instance's currently-verified application keys, using the
// cache when possible, coalescing concurrent refreshes for the same
// instance, and falling back to the last verified material (marked
// FreshnessStale) when the RP cannot be reached.
func (r *CachedResolver) Resolve(ctx context.Context, instance InstanceRef, maxCacheAgeSeconds *int64) (ResolveResult, error) {
	now := r.opts.Now()

	if entry, ok := r.getFresh(instance, now); ok {
		return ResolveResult{
			Keys:          r.verify(entry, instance, now),
			Freshness:     FreshnessFresh,
			FetchedAt:     entry.fetchedAt,
			RPCacheStatus: entry.rpCacheStatus,
		}, nil
	}

	fetched, fetchErr := r.sf.do(instance, func() (cacheEntry, error) {
		return r.fetch(ctx, instance, maxCacheAgeSeconds)
	})

	if fetchErr == nil {
		r.put(fetched)
		return ResolveResult{
			Keys:          r.verify(fetched, instance, now),
			Freshness:     FreshnessRefreshed,
			FetchedAt:     fetched.fetchedAt,
			RPCacheStatus: fetched.rpCacheStatus,
		}, nil
	}

	// The RP could not be reached (or refused/failed the request). Fall
	// back to the last verified material for this instance, if any —
	// marked stale, never presented as current trust.
	if entry, ok := r.getAny(instance); ok {
		return ResolveResult{
			Keys:          r.verify(entry, instance, now),
			Freshness:     FreshnessStale,
			FetchedAt:     entry.fetchedAt,
			RPCacheStatus: entry.rpCacheStatus,
		}, nil
	}
	return ResolveResult{}, &NoCachedResultError{Detail: fetchErr.Error()}
}

// verify re-runs full verification (signatures + classification) against
// entry's raw material at `now`. Domain-key revocations are applied to the
// domain key set first — see domainkeys.go's applyDomainKeyRevocations.
func (r *CachedResolver) verify(entry cacheEntry, instance InstanceRef, now time.Time) VerifiedApplicationKeySet {
	domainKeys := applyDomainKeyRevocations(entry.homeDomainKeys, entry.homeDomainKeyRevocations, instance.SubjectDomain)
	return VerifyApplicationKeySet(entry.applicationKeys, entry.applicationKeyRevocations, domainKeys, instance, now, r.opts.SkewSeconds)
}

// fetch calls the RP and confirms the response is actually about the
// instance requested — the RP echoes the canonical tuple back, and this SDK
// checks it rather than trusting the request/response pairing alone.
func (r *CachedResolver) fetch(ctx context.Context, instance InstanceRef, maxCacheAgeSeconds *int64) (cacheEntry, error) {
	resp, err := r.client.ResolveApplicationKeys(ctx, api.RpResolveApplicationKeysRequest{
		SubjectUserId:      instance.SubjectUserID,
		SubjectDomain:      instance.SubjectDomain,
		ApplicationId:      instance.ApplicationID,
		InstanceId:         instance.InstanceID,
		MaxCacheAgeSeconds: maxCacheAgeSeconds,
	})
	if err != nil {
		return cacheEntry{}, err
	}
	if resp.SubjectUserId != instance.SubjectUserID || resp.SubjectDomain != instance.SubjectDomain ||
		resp.ApplicationId != instance.ApplicationID || resp.InstanceId != instance.InstanceID {
		return cacheEntry{}, &ApplicationKeyError{Kind: ErrIdentityMismatch, Detail: "RP response instance does not match the request"}
	}
	return cacheEntry{
		instance:                  instance,
		applicationKeys:           resp.ApplicationKeys,
		applicationKeyRevocations: resp.ApplicationKeyRevocations,
		homeDomainKeys:            resp.HomeDomainKeys,
		homeDomainKeyRevocations:  resp.HomeDomainKeyRevocations,
		fetchedAt:                 r.opts.Now(),
		rpCacheStatus:             resp.CacheStatus,
	}, nil
}

// ---------------------------------------------------------------------------
// Bounded LRU cache
// ---------------------------------------------------------------------------

// getFresh returns the cached entry for instance if one exists AND is
// within TTL, touching its LRU position.
func (r *CachedResolver) getFresh(instance InstanceRef, now time.Time) (cacheEntry, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.entries[instance]
	if !ok || now.Sub(e.fetchedAt) >= r.opts.TTL {
		return cacheEntry{}, false
	}
	r.order.MoveToFront(e.elem)
	return *e, true
}

// getAny returns the cached entry for instance regardless of TTL (the
// stale-fallback path), touching its LRU position.
func (r *CachedResolver) getAny(instance InstanceRef) (cacheEntry, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.entries[instance]
	if !ok {
		return cacheEntry{}, false
	}
	r.order.MoveToFront(e.elem)
	return *e, true
}

// put inserts or replaces the cache entry for entry.instance, evicting the
// least-recently-used entry if the cache is at MaxEntries and this is a new
// key.
func (r *CachedResolver) put(entry cacheEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if existing, ok := r.entries[entry.instance]; ok {
		entry.elem = existing.elem
		*existing = entry
		r.order.MoveToFront(existing.elem)
		return
	}

	if len(r.entries) >= r.opts.MaxEntries {
		back := r.order.Back()
		if back != nil {
			evicted := back.Value.(*cacheEntry)
			delete(r.entries, evicted.instance)
			r.order.Remove(back)
		}
	}

	stored := entry
	stored.elem = r.order.PushFront(&stored)
	r.entries[entry.instance] = &stored
}

// Len reports how many instances are currently cached (test/observability
// helper).
func (r *CachedResolver) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.entries)
}

// ---------------------------------------------------------------------------
// Singleflight: coalesce concurrent fetches for the same instance
// ---------------------------------------------------------------------------

// singleflightGroup is a minimal, hand-rolled equivalent of
// golang.org/x/sync/singleflight.Group scoped to InstanceRef keys — a
// handful of lines, not worth a dependency for.
type singleflightGroup struct {
	mu    sync.Mutex
	calls map[InstanceRef]*singleflightCall
}

type singleflightCall struct {
	wg  sync.WaitGroup
	val cacheEntry
	err error
}

func newSingleflightGroup() singleflightGroup {
	return singleflightGroup{calls: make(map[InstanceRef]*singleflightCall)}
}

// do runs fn for key, or waits for and returns the result of an in-flight
// call already running for the same key. Only the FIRST caller's context
// drives the actual fetch (the same tradeoff golang.org/x/sync/singleflight
// makes) — a later caller's cancellation/deadline does not abort a fetch it
// merely joined, and a later caller's own ctx is otherwise unused for that
// fetch. Acceptable here: one instance's key material does not vary by
// caller, so joining an in-flight fetch is always correct, only the timing
// characteristics differ.
func (g *singleflightGroup) do(key InstanceRef, fn func() (cacheEntry, error)) (cacheEntry, error) {
	g.mu.Lock()
	if c, ok := g.calls[key]; ok {
		g.mu.Unlock()
		c.wg.Wait()
		return c.val, c.err
	}
	c := &singleflightCall{}
	c.wg.Add(1)
	g.calls[key] = c
	g.mu.Unlock()

	c.val, c.err = fn()
	c.wg.Done()

	g.mu.Lock()
	delete(g.calls, key)
	g.mu.Unlock()

	return c.val, c.err
}
