package webpush

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"math/big"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Cache stats for monitoring (optional)
var (
	vapidCacheHits   uint64
	vapidCacheMisses uint64
)

// GetVAPIDCacheStats returns cache hit/miss stats for monitoring
func GetVAPIDCacheStats() (hits, misses uint64) {
	return atomic.LoadUint64(&vapidCacheHits), atomic.LoadUint64(&vapidCacheMisses)
}

// Cache for VAPID authorization headers (keyed by privateKey + publicKey + audience)
var vapidHeaderCache sync.Map

// Cache for parsed private keys (keyed by vapidPrivateKey)
var privateKeyCache sync.Map

// vapidCacheEntry stores cached VAPID header with expiration
type vapidCacheEntry struct {
	header     string
	expiration time.Time
}

// cacheMargin is how long before expiration we consider cache invalid (safety margin)
const cacheMargin = 30 * time.Minute

// GenerateVAPIDKeys will create a private and public VAPID key pair
func GenerateVAPIDKeys() (privateKey, publicKey string, err error) {
	// Get the private key from the P256 curve
	curve := elliptic.P256()

	private, x, y, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		return
	}

	public := elliptic.Marshal(curve, x, y)

	// Convert to base64
	publicKey = base64.RawURLEncoding.EncodeToString(public)
	privateKey = base64.RawURLEncoding.EncodeToString(private)

	return
}

// Generates the ECDSA public and private keys for the JWT encryption
func generateVAPIDHeaderKeys(privateKey []byte) *ecdsa.PrivateKey {
	// Public key
	curve := elliptic.P256()
	px, py := curve.ScalarMult(
		curve.Params().Gx,
		curve.Params().Gy,
		privateKey,
	)

	pubKey := ecdsa.PublicKey{
		Curve: curve,
		X:     px,
		Y:     py,
	}

	// Private key
	d := &big.Int{}
	d.SetBytes(privateKey)

	return &ecdsa.PrivateKey{
		PublicKey: pubKey,
		D:         d,
	}
}

// getVAPIDAuthorizationHeader returns a cached VAPID authorization header if available,
// otherwise generates a new one and caches it.
func getVAPIDAuthorizationHeader(
	endpoint,
	subscriber,
	vapidPublicKey,
	vapidPrivateKey string,
	expiration time.Time,
) (string, error) {
	// Parse endpoint to get audience
	subURL, err := url.Parse(endpoint)
	if err != nil {
		return "", err
	}

	audience := subURL.Scheme + "://" + subURL.Host

	// Create cache key: privateKey + publicKey + audience
	cacheKey := vapidPrivateKey + "|" + vapidPublicKey + "|" + audience

	// Check cache for existing valid header
	if cached, ok := vapidHeaderCache.Load(cacheKey); ok {
		entry := cached.(vapidCacheEntry)
		// Return cached header if still valid (with safety margin)
		if time.Now().Add(cacheMargin).Before(entry.expiration) {
			// atomic.AddUint64(&vapidCacheHits, 1)
			return entry.header, nil
		}
		// Cache expired, delete it
		vapidHeaderCache.Delete(cacheKey)
	}

	// atomic.AddUint64(&vapidCacheMisses, 1)

	// Unless subscriber is an HTTPS URL, assume an e-mail address
	if !strings.HasPrefix(subscriber, "https:") {
		subscriber = "mailto:" + subscriber
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"aud": audience,
		"exp": expiration.Unix(),
		"sub": subscriber,
	})

	// Get or create cached private key
	privKey, err := getCachedPrivateKey(vapidPrivateKey)
	if err != nil {
		return "", err
	}

	// Sign token with private key
	jwtString, err := token.SignedString(privKey)
	if err != nil {
		return "", err
	}

	// Decode the VAPID public key
	pubKey, err := decodeVapidKey(vapidPublicKey)
	if err != nil {
		return "", err
	}

	header := "vapid t=" + jwtString + ", k=" + base64.RawURLEncoding.EncodeToString(pubKey)

	// Cache the header
	vapidHeaderCache.Store(cacheKey, vapidCacheEntry{
		header:     header,
		expiration: expiration,
	})

	return header, nil
}

// getCachedPrivateKey returns a cached parsed private key or parses and caches a new one
func getCachedPrivateKey(vapidPrivateKey string) (*ecdsa.PrivateKey, error) {
	// Check cache
	if cached, ok := privateKeyCache.Load(vapidPrivateKey); ok {
		return cached.(*ecdsa.PrivateKey), nil
	}

	// Decode and parse the private key
	decodedVapidPrivateKey, err := decodeVapidKey(vapidPrivateKey)
	if err != nil {
		return nil, err
	}

	privKey := generateVAPIDHeaderKeys(decodedVapidPrivateKey)

	// Cache the parsed key
	privateKeyCache.Store(vapidPrivateKey, privKey)

	return privKey, nil
}

// Need to decode the vapid private key in multiple base64 formats
// Solution from: https://github.com/SherClockHolmes/webpush-go/issues/29
func decodeVapidKey(key string) ([]byte, error) {
	bytes, err := base64.URLEncoding.DecodeString(key)
	if err == nil {
		return bytes, nil
	}

	return base64.RawURLEncoding.DecodeString(key)
}
