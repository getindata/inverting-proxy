// TODO: Describe package
// TODO: Example usage
package cache_cookies

import (
	"fmt"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"sync"
	"time"

	"github.com/golang/groupcache/lru"
	"github.com/google/inverting-proxy/agent/metrics"
	"github.com/google/uuid"
	"golang.org/x/net/publicsuffix"
)

type cacheCookieResponseWriter struct {
	c             *Cache
	sessionID     string
	urlForCookies *url.URL
	metricHandler *metrics.MetricHandler

	wrapped     http.ResponseWriter
	wroteHeader bool
}

func (w *cacheCookieResponseWriter) Header() http.Header {
	return w.wrapped.Header()
}

func (w *cacheCookieResponseWriter) Write(bs []byte) (int, error) {
	if !w.wroteHeader {
		statusCode := http.StatusOK
		w.WriteHeader(statusCode)
		w.metricHandler.WriteResponseCodeMetric(statusCode)
	}
	return w.wrapped.Write(bs)
}

func (w *cacheCookieResponseWriter) WriteHeader(statusCode int) {
	if w.wroteHeader {
		// Multiple calls ot WriteHeader are no-ops
		return
	}
	w.wroteHeader = true
	header := w.Header()
	cookiesToAdd := (&http.Response{Header: header}).Cookies()
	cookieJar, err := w.c.cachedCookieJar()
	if err != nil {
		log.Printf("Failure reading a cached cookie jar: %v", err)
	}
	if len(cookiesToAdd) == 0 {
		// There were no cookies to intercept
		w.wrapped.WriteHeader(statusCode)
		return
	}
	log.Printf("Cookies to add: %v for url: %v", cookiesToAdd, w.urlForCookies)
	log.Printf("Cookies in the jar: %v", cookieJar.Cookies(w.urlForCookies))
	cookieJar.SetCookies(w.urlForCookies, append(cookiesToAdd, cookieJar.Cookies(w.urlForCookies)...))
	w.wrapped.WriteHeader(statusCode)
}

type sessionHandler struct {
	c             *Cache
	headerPath    string
	wrapped       http.Handler
	metricHandler *metrics.MetricHandler
}

func (h *sessionHandler) extractSessionID(r *http.Request) string {
	sessionCookie := r.Header.Get(h.headerPath)
	if sessionCookie == "" {
		// There is no session cookie, so we do not (yet) have a session
		return ""
	}
	return sessionCookie
}

func (h *sessionHandler) restoreSession(r *http.Request, cachedCookies []*http.Cookie) {
	existingCookies := r.Cookies()
	r.Header.Del("Cookie")
	log.Printf("Restoring session existing cookies: %v", existingCookies)
	for _, c := range existingCookies {
		r.AddCookie(c)
	}
	log.Printf("Restoring session cached cookies: %v", cachedCookies)
	// Restore any cached cookies from the session
	for _, c := range cachedCookies {
		r.AddCookie(c)
	}
}

// ServeHTTP implements the http.Handler interface
func (h *sessionHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	urlForCookies := *(r.URL)
	log.Printf("Handling request for %s", urlForCookies.String())
	log.Printf("Request headers: %v", r.Header)
	urlForCookies.Scheme = "https"
	urlForCookies.Host = r.Host
	sessionID := h.extractSessionID(r)
	cachedCookieJar, err := h.c.cachedCookieJar()
	if err != nil {
		// There is a session cookie but we could not fetch the corresponding cookie jar.
		//
		// This should not happen and represents an internal error in the session handling logic.
		log.Printf("Failure reading the cookie jar for session %q: %v", sessionID, err)
		statusCode := http.StatusInternalServerError
		http.Error(w, fmt.Sprintf("Internal error reading the session %q", sessionID), statusCode)
		h.metricHandler.WriteResponseCodeMetric(statusCode)
		return
	}
	cachedCookies := cachedCookieJar.Cookies(&urlForCookies)
	h.restoreSession(r, cachedCookies)
	w = &cacheCookieResponseWriter{
		c:             h.c,
		sessionID:     sessionID,
		urlForCookies: &urlForCookies,
		wrapped:       w,
		metricHandler: h.metricHandler,
	}
	h.wrapped.ServeHTTP(w, r)
}

// SessionHandler returns an instance of `http.Handler` that wraps the given handler and adds proxy-side session tracking.
func (c *Cache) SessionHandler(headerPath string, wrapped http.Handler, metricHandler *metrics.MetricHandler) http.Handler {
	if c == nil {
		return wrapped
	}
	return &sessionHandler{
		c:             c,
		headerPath:    headerPath,
		wrapped:       wrapped,
		metricHandler: metricHandler,
	}
}

// Cache represents a LRU cache to store sessions
type Cache struct {
	sessionId            string
	sessionCookieTimeout time.Duration
	disableSSLForTest    bool

	cache *lru.Cache
	mu    sync.Mutex
}

// NewCache initializes an LRU session cache
func NewCache(sessionCookieTimeout time.Duration, cookieCacheLimit int, disableSSLForTest bool) *Cache {
	return &Cache{
		sessionId:            uuid.New().String(),
		sessionCookieTimeout: sessionCookieTimeout,
		disableSSLForTest:    disableSSLForTest,
		cache:                lru.New(cookieCacheLimit),
	}
}

// addJarToCache takes a Jar from http.Client and stores it in a cache
func (c *Cache) addJarToCache(sessionID string, jar http.CookieJar) {
	c.mu.Lock()
	c.cache.Add(sessionID, jar)
	c.mu.Unlock()
}

// cachedCookieJar returns the CookieJar mapped to the sessionID
func (c *Cache) cachedCookieJar() (jar http.CookieJar, err error) {
	val, ok := c.cache.Get(c.sessionId)
	if !ok {
		options := cookiejar.Options{
			PublicSuffixList: publicsuffix.List,
		}
		jar, err = cookiejar.New(&options)
		c.addJarToCache(c.sessionId, jar)
		return jar, err
	}

	jar, ok = val.(http.CookieJar)
	if !ok {
		return nil, fmt.Errorf("Internal error; unexpected type for value (%+v) stored in the cookie jar cache", val)
	}
	return jar, nil
}
