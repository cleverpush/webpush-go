package webpush

import (
	"testing"
	"time"
)

func TestVAPIDCaching(t *testing.T) {
	// Generate test VAPID keys
	privateKey, publicKey, err := GenerateVAPIDKeys()
	if err != nil {
		t.Fatalf("Failed to generate VAPID keys: %v", err)
	}

	endpoint := "https://fcm.googleapis.com/fcm/send/test-subscription-id"
	subscriber := "test@example.com"
	expiration := time.Now().Add(12 * time.Hour)

	// Reset counters
	vapidCacheHits = 0
	vapidCacheMisses = 0

	// First call - should be a cache MISS
	header1, err := getVAPIDAuthorizationHeader(endpoint, subscriber, publicKey, privateKey, expiration)
	if err != nil {
		t.Fatalf("First call failed: %v", err)
	}

	hits1, misses1 := GetVAPIDCacheStats()
	if hits1 != 0 || misses1 != 1 {
		t.Errorf("Expected 0 hits, 1 miss after first call. Got %d hits, %d misses", hits1, misses1)
	}

	// Second call with same params - should be a cache HIT
	header2, err := getVAPIDAuthorizationHeader(endpoint, subscriber, publicKey, privateKey, expiration)
	if err != nil {
		t.Fatalf("Second call failed: %v", err)
	}

	hits2, misses2 := GetVAPIDCacheStats()
	if hits2 != 1 || misses2 != 1 {
		t.Errorf("Expected 1 hit, 1 miss after second call. Got %d hits, %d misses", hits2, misses2)
	}

	// Headers should be identical
	if header1 != header2 {
		t.Error("Cached header should be identical to original")
	}

	// Third call with DIFFERENT endpoint origin - should be a cache MISS
	endpoint2 := "https://updates.push.services.mozilla.com/wpush/v1/test-subscription-id"
	_, err = getVAPIDAuthorizationHeader(endpoint2, subscriber, publicKey, privateKey, expiration)
	if err != nil {
		t.Fatalf("Third call failed: %v", err)
	}

	hits3, misses3 := GetVAPIDCacheStats()
	if hits3 != 1 || misses3 != 2 {
		t.Errorf("Expected 1 hit, 2 misses after third call (different origin). Got %d hits, %d misses", hits3, misses3)
	}

	// Fourth call - same as first endpoint - should be a cache HIT
	_, err = getVAPIDAuthorizationHeader(endpoint, subscriber, publicKey, privateKey, expiration)
	if err != nil {
		t.Fatalf("Fourth call failed: %v", err)
	}

	hits4, misses4 := GetVAPIDCacheStats()
	if hits4 != 2 || misses4 != 2 {
		t.Errorf("Expected 2 hits, 2 misses after fourth call. Got %d hits, %d misses", hits4, misses4)
	}

	t.Logf("✅ VAPID Caching Test Passed! Final stats: %d hits, %d misses", hits4, misses4)
}

func BenchmarkVAPIDWithCaching(b *testing.B) {
	privateKey, publicKey, _ := GenerateVAPIDKeys()
	endpoint := "https://fcm.googleapis.com/fcm/send/test-subscription-id"
	subscriber := "test@example.com"
	expiration := time.Now().Add(12 * time.Hour)

	// Warm up cache
	getVAPIDAuthorizationHeader(endpoint, subscriber, publicKey, privateKey, expiration)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		getVAPIDAuthorizationHeader(endpoint, subscriber, publicKey, privateKey, expiration)
	}

	hits, misses := GetVAPIDCacheStats()
	b.Logf("Cache hits: %d, misses: %d", hits, misses)
}
