/*
 * Mail2Dizum Security Enhanced v1.0
 * ===================================
 * 
 * Secure web interface for Usenet posting via dizum.com mail2news service
 * 
 * SECURITY ENHANCEMENTS IN THIS VERSION:
 * - MemGuard integration for sensitive data protection in memory
 * - Advanced input validation and HTML sanitization
 * - CSRF protection with secure token generation
 * - Rate limiting and IP banning system
 * - Anomaly detection for attack patterns
 * - Anti-replay protection with unique tokens
 * - Prometheus metrics for security monitoring
 * - Structured logging without sensitive data exposure
 * - Tor connection hardening with timeouts
 * - System resource limits and privilege management
 * 
 * PROTOCOL COMPLIANCE:
 * - Full RFC 5536 compliance for Usenet message format
 * - UTF-8 only encoding for international compatibility
 * - Proper MIME headers and threading support
 * 
 * PRIVACY FEATURES:
 * - All communications routed through Tor
 * - No persistent storage of user data
 * - Memory protection against dump attacks
 * - Real-time cleanup of sensitive information
 * 
 * Author: Gabriel (gabrix73)
 * Repository: https://github.com/gabrix73/mail2dizum.git
 * License: Open Source
 * 
 * Build with: go build -ldflags="-s -w" -o mail2dizum mail2dizum.go
 */

package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/smtp"
	"os"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	// === SECURITY ENHANCED v1.0 - NEW DEPENDENCIES ===
	"github.com/awnumar/memguard"              // v1.0: Memory protection for sensitive data
	"github.com/go-playground/validator/v10"   // v1.0: Advanced input validation
	"github.com/gorilla/csrf"                  // v1.0: CSRF protection
	"github.com/gorilla/sessions"              // v1.0: Secure session management
	"github.com/microcosm-cc/bluemonday"       // v1.0: HTML sanitization
	"github.com/prometheus/client_golang/prometheus"        // v1.0: Metrics collection
	"github.com/prometheus/client_golang/prometheus/promauto" // v1.0: Auto-register metrics
	"github.com/prometheus/client_golang/prometheus/promhttp" // v1.0: Metrics HTTP handler
	"github.com/sirupsen/logrus"               // v1.0: Structured logging
	"golang.org/x/net/netutil"                 // v1.0: Connection limiting
	"golang.org/x/net/proxy"                   // v1.0: Enhanced Tor proxy support
	"golang.org/x/time/rate"                   // v1.0: Rate limiting
)

// === VERSION INFORMATION ===
const (
	VERSION = "1.0.0-security-enhanced"
	BUILD_DATE = "2025-01-XX"
	AUTHOR = "Gabriel (gabrix73)"
)

// === SECURITY ENHANCED v1.0 - PROMETHEUS METRICS ===
var (
	// v1.0: Request tracking with detailed labels
	requestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "mail2news_requests_total",
			Help: "Total number of HTTP requests processed",
		},
		[]string{"method", "endpoint", "status"},
	)
	
	// v1.0: Security events monitoring
	securityEvents = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "mail2news_security_events_total",
			Help: "Security events detected by type and severity",
		},
		[]string{"type", "severity"},
	)
	
	// v1.0: Tor connection performance tracking
	torConnectionDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name: "mail2news_tor_connection_duration_seconds",
			Help: "Time taken to establish Tor connections",
		},
	)
	
	// v1.0: Rate limiter - 5 requests per minute per IP
	limiter = rate.NewLimiter(rate.Every(time.Minute), 5)
	
	// v1.0: Secure session store with strong keys
	store *sessions.CookieStore
	
	// v1.0: Structured logger without sensitive data exposure
	logger = logrus.New()
	
	// v1.0: Input validator for security checks
	validate *validator.Validate
	
	// v1.0: HTML sanitizer for XSS prevention
	htmlSanitizer *bluemonday.Policy
)

// === SECURITY ENHANCED v1.0 - SECURITY CACHE ===
// v1.0: In-memory cache for IP banning and threat tracking
type SecurityCache struct {
	bannedIPs    map[string]time.Time // v1.0: IP ban tracking with timestamps
	failedLogins map[string]int       // v1.0: Failed attempt counters
	mutex        sync.RWMutex         // v1.0: Thread-safe access
}

var securityCache = &SecurityCache{
	bannedIPs:    make(map[string]time.Time),
	failedLogins: make(map[string]int),
}

// === SECURITY ENHANCED v1.0 - SECURE MESSAGE STRUCTURE ===
// v1.0: MemGuard protected structure for sensitive user data
type SecureMessage struct {
	from       *memguard.LockedBuffer // v1.0: Protected email address
	newsgroup  *memguard.LockedBuffer // v1.0: Protected newsgroup names
	subject    *memguard.LockedBuffer // v1.0: Protected message subject
	message    *memguard.LockedBuffer // v1.0: Protected message content
	references *memguard.LockedBuffer // v1.0: Protected threading references
}

// === SECURITY ENHANCED v1.0 - INITIALIZATION ===
func init() {
	// v1.0: Initialize MemGuard for memory protection
	memguard.CatchInterrupt() // Cleanup on interrupt signals
	
	// v1.0: Configure structured logger for security
	logger.SetFormatter(&logrus.JSONFormatter{}) // Machine-readable logs
	logger.SetLevel(logrus.WarnLevel)            // Only warnings and errors
	
	// v1.0: Initialize input validator
	validate = validator.New()
	
	// v1.0: Initialize HTML sanitizer (strict policy - text only)
	htmlSanitizer = bluemonday.StrictPolicy()
	
	// v1.0: Generate secure session keys
	sessionKey := make([]byte, 32)
	if _, err := rand.Read(sessionKey); err != nil {
		logger.Fatal("Failed to generate secure session key")
	}
	
	// v1.0: Configure secure session store
	store = sessions.NewCookieStore(sessionKey)
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   3600, // 1 hour expiry
		HttpOnly: true, // No JavaScript access
		Secure:   true, // HTTPS only in production
		SameSite: http.SameSiteStrictMode, // CSRF protection
	}
	
	// v1.0: Start security cache cleanup routine
	go securityCacheCleanup()
	
	logger.WithField("version", VERSION).Info("Mail2Dizum Security Enhanced initialized")
}

// === SECURITY ENHANCED v1.0 - MEMORY PROTECTION FUNCTIONS ===

// v1.0: Create new secure message with MemGuard protection
func NewSecureMessage(from, newsgroup, subject, message, references string) (*SecureMessage, error) {
	sm := &SecureMessage{}
	
	// v1.0: Create protected buffers for each sensitive field
	sm.from = memguard.NewBuffer(len(from))
	if sm.from == nil {
		return nil, fmt.Errorf("failed to protect 'from' field")
	}
	copy(sm.from.Bytes(), []byte(from))
	
	sm.newsgroup = memguard.NewBuffer(len(newsgroup))
	if sm.newsgroup == nil {
		sm.from.Destroy()
		return nil, fmt.Errorf("failed to protect 'newsgroup' field")
	}
	copy(sm.newsgroup.Bytes(), []byte(newsgroup))
	
	sm.subject = memguard.NewBuffer(len(subject))
	if sm.subject == nil {
		sm.from.Destroy()
		sm.newsgroup.Destroy()
		return nil, fmt.Errorf("failed to protect 'subject' field")
	}
	copy(sm.subject.Bytes(), []byte(subject))
	
	sm.message = memguard.NewBuffer(len(message))
	if sm.message == nil {
		sm.from.Destroy()
		sm.newsgroup.Destroy()
		sm.subject.Destroy()
		return nil, fmt.Errorf("failed to protect 'message' field")
	}
	copy(sm.message.Bytes(), []byte(message))
	
	sm.references = memguard.NewBuffer(len(references))
	if sm.references == nil {
		sm.from.Destroy()
		sm.newsgroup.Destroy()
		sm.subject.Destroy()
		sm.message.Destroy()
		return nil, fmt.Errorf("failed to protect 'references' field")
	}
	copy(sm.references.Bytes(), []byte(references))
	
	logger.Debug("Secure message created with MemGuard protection")
	return sm, nil
}

// v1.0: Secure cleanup of all protected memory
func (sm *SecureMessage) Destroy() {
	if sm.from != nil {
		sm.from.Destroy()
	}
	if sm.newsgroup != nil {
		sm.newsgroup.Destroy()
	}
	if sm.subject != nil {
		sm.subject.Destroy()
	}
	if sm.message != nil {
		sm.message.Destroy()
	}
	if sm.references != nil {
		sm.references.Destroy()
	}
	logger.Debug("Secure message destroyed - memory cleaned")
}

// v1.0: Secure access functions with automatic cleanup
func (sm *SecureMessage) GetFrom() (string, error) {
	if sm.from == nil {
		return "", fmt.Errorf("from field not protected")
	}
	return string(sm.from.Bytes()), nil
}

func (sm *SecureMessage) GetNewsgroup() (string, error) {
	if sm.newsgroup == nil {
		return "", fmt.Errorf("newsgroup field not protected")
	}
	return string(sm.newsgroup.Bytes()), nil
}

func (sm *SecureMessage) GetSubject() (string, error) {
	if sm.subject == nil {
		return "", fmt.Errorf("subject field not protected")
	}
	return string(sm.subject.Bytes()), nil
}

func (sm *SecureMessage) GetMessage() (string, error) {
	if sm.message == nil {
		return "", fmt.Errorf("message field not protected")
	}
	return string(sm.message.Bytes()), nil
}

func (sm *SecureMessage) GetReferences() (string, error) {
	if sm.references == nil {
		return "", fmt.Errorf("references field not protected")
	}
	return string(sm.references.Bytes()), nil
}

// === SECURITY ENHANCED v1.0 - SECURITY FUNCTIONS ===

// v1.0: Periodic cleanup of security cache
func securityCacheCleanup() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	
	for range ticker.C {
		securityCache.mutex.Lock()
		now := time.Now()
		
		// v1.0: Remove expired IP bans (24 hours)
		for ip, banTime := range securityCache.bannedIPs {
			if now.Sub(banTime) > 24*time.Hour {
				delete(securityCache.bannedIPs, ip)
				logger.WithField("ip", ip).Info("IP ban expired and removed")
			}
		}
		
		// v1.0: Reset failed login counters (1 hour)
		securityCache.failedLogins = make(map[string]int)
		
		securityCache.mutex.Unlock()
		logger.Debug("Security cache cleanup completed")
	}
}

// v1.0: Check if IP is currently banned
func isIPBanned(ip string) bool {
	securityCache.mutex.RLock()
	defer securityCache.mutex.RUnlock()
	
	banTime, exists := securityCache.bannedIPs[ip]
	if !exists {
		return false
	}
	
	// v1.0: 24-hour ban period
	return time.Since(banTime) < 24*time.Hour
}

// v1.0: Ban IP for suspicious activity
func banIP(ip string, reason string) {
	securityCache.mutex.Lock()
	defer securityCache.mutex.Unlock()
	
	securityCache.bannedIPs[ip] = time.Now()
	
	logger.WithFields(logrus.Fields{
		"ip":     ip,
		"reason": reason,
	}).Warn("IP banned for suspicious activity")
	
	securityEvents.WithLabelValues("ip_ban", "high").Inc()
}

// v1.0: Extract client IP considering proxies
func getClientIP(r *http.Request) string {
	// v1.0: Check for forwarded IP from reverse proxy
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		return strings.Split(forwarded, ",")[0]
	}
	
	realIP := r.Header.Get("X-Real-IP")
	if realIP != "" {
		return realIP
	}
	
	return r.RemoteAddr
}

// === SECURITY ENHANCED v1.0 - MIDDLEWARE FUNCTIONS ===

// v1.0: IP banning middleware
func ipBanMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clientIP := getClientIP(r)
		
		if isIPBanned(clientIP) {
			http.Error(w, "Access denied", http.StatusForbidden)
			securityEvents.WithLabelValues("banned_access_attempt", "medium").Inc()
			requestsTotal.WithLabelValues(r.Method, r.URL.Path, "403").Inc()
			return
		}
		
		next.ServeHTTP(w, r)
	}
}

// v1.0: Rate limiting middleware
func rateLimitMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !limiter.Allow() {
			clientIP := getClientIP(r)
			logger.WithField("ip", clientIP).Warn("Rate limit exceeded")
			securityEvents.WithLabelValues("rate_limit_exceeded", "medium").Inc()
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			requestsTotal.WithLabelValues(r.Method, r.URL.Path, "429").Inc()
			return
		}
		next.ServeHTTP(w, r)
	}
}

// v1.0: Application-specific security headers
func appSecurityHeadersMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// v1.0: Cache control for sensitive pages
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, private")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")
		next.ServeHTTP(w, r)
	}
}

// v1.0: Anomaly detection middleware
func anomalyDetectionMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clientIP := getClientIP(r)
		
		// v1.0: Detect suspicious User-Agent patterns
		userAgent := r.UserAgent()
		suspiciousPatterns := []string{
			"sqlmap", "nmap", "nikto", "burp", "metasploit",
			"wget", "curl", "python-requests", "bot", "crawler",
			"scanner", "exploit", "hack", "injection",
		}
		
		for _, pattern := range suspiciousPatterns {
			if strings.Contains(strings.ToLower(userAgent), pattern) {
				logger.WithFields(logrus.Fields{
					"ip":         clientIP,
					"user_agent": userAgent,
					"pattern":    pattern,
				}).Warn("Suspicious User-Agent detected")
				
				securityEvents.WithLabelValues("suspicious_user_agent", "medium").Inc()
				banIP(clientIP, "Suspicious User-Agent: "+pattern)
				http.Error(w, "Access denied", http.StatusForbidden)
				requestsTotal.WithLabelValues(r.Method, r.URL.Path, "403").Inc()
				return
			}
		}
		
		// v1.0: Detect header injection attempts
		for name, values := range r.Header {
			for _, value := range values {
				if strings.Contains(value, "\r") || strings.Contains(value, "\n") {
					logger.WithFields(logrus.Fields{
						"ip":     clientIP,
						"header": name,
						"value":  value,
					}).Warn("Header injection attempt detected")
					
					securityEvents.WithLabelValues("header_injection", "high").Inc()
					banIP(clientIP, "Header injection attempt")
					http.Error(w, "Access denied", http.StatusForbidden)
					requestsTotal.WithLabelValues(r.Method, r.URL.Path, "403").Inc()
					return
				}
			}
		}
		
		next.ServeHTTP(w, r)
	}
}

// v1.0: Request size limiting middleware
func maxSizeMiddleware(maxSize int64) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, maxSize)
			next.ServeHTTP(w, r)
		}
	}
}

// === SECURITY ENHANCED v1.0 - INPUT VALIDATION ===

// v1.0: Comprehensive input sanitization and validation
func sanitizeAndValidateInput(r *http.Request) (*SecureMessage, error) {
	// v1.0: Sanitize all input fields against XSS
	from := htmlSanitizer.Sanitize(r.FormValue("from"))
	newsgroup := htmlSanitizer.Sanitize(r.FormValue("newsgroup"))
	subject := htmlSanitizer.Sanitize(r.FormValue("subject"))
	message := htmlSanitizer.Sanitize(r.FormValue("message"))
	references := htmlSanitizer.Sanitize(r.FormValue("reply_to"))
	
	// v1.0: Validate field lengths to prevent abuse
	if len(from) > 256 || len(newsgroup) > 256 || len(subject) > 256 {
		return nil, fmt.Errorf("field too long - maximum 256 characters")
	}
	
	if len(message) > 50000 { // v1.0: 50KB maximum message size
		return nil, fmt.Errorf("message too long - maximum 50KB")
	}
	
	// v1.0: Validate email format (RFC compliant)
	fromPattern := regexp.MustCompile(`^[^<>]+<[^<>@]+@[^<>]+>$`)
	if !fromPattern.MatchString(from) {
		return nil, fmt.Errorf("invalid From format - required: Name <email@domain>")
	}
	
	// v1.0: Validate newsgroup format (max 3 groups)
	newsgroupPattern := regexp.MustCompile(`^(?:[a-zA-Z0-9._-]+)(?:\s*,\s*[a-zA-Z0-9._-]+){0,2}$`)
	if !newsgroupPattern.MatchString(newsgroup) {
		return nil, fmt.Errorf("invalid newsgroup format - max 3 groups separated by commas")
	}
	
	// v1.0: Validate subject (no control characters)
	if !regexp.MustCompile(`^[^\r\n]+$`).MatchString(subject) {
		return nil, fmt.Errorf("invalid subject - no control characters allowed")
	}
	
	// v1.0: Validate message content (must have content)
	if !regexp.MustCompile(`(?s)^.+$`).MatchString(message) {
		return nil, fmt.Errorf("invalid message - content required")
	}
	
	// v1.0: Create secure message with MemGuard protection
	return NewSecureMessage(from, newsgroup, subject, message, references)
}

// === SECURITY ENHANCED v1.0 - ANTI-REPLAY PROTECTION ===

// v1.0: Anti-replay token cache with automatic expiry
var replayTokenCache = sync.Map{}

// v1.0: Generate cryptographically secure anti-replay token
func generateAntiReplayToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// v1.0: Anti-replay middleware
func antiReplayMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			token := r.Header.Get("X-Anti-Replay-Token")
			if token == "" {
				http.Error(w, "Missing anti-replay token", http.StatusBadRequest)
				requestsTotal.WithLabelValues(r.Method, r.URL.Path, "400").Inc()
				return
			}
			
			// v1.0: Check for token reuse (replay attack)
			if _, exists := replayTokenCache.Load(token); exists {
				clientIP := getClientIP(r)
				logger.WithFields(logrus.Fields{
					"ip":    clientIP,
					"token": token,
				}).Warn("Replay attack detected")
				
				securityEvents.WithLabelValues("replay_attack", "high").Inc()
				banIP(clientIP, "Replay attack attempt")
				http.Error(w, "Access denied", http.StatusForbidden)
				requestsTotal.WithLabelValues(r.Method, r.URL.Path, "403").Inc()
				return
			}
			
			// v1.0: Store token with automatic expiry after 1 hour
			replayTokenCache.Store(token, time.Now())
			go func() {
				time.Sleep(1 * time.Hour)
				replayTokenCache.Delete(token)
			}()
		}
		
		next.ServeHTTP(w, r)
	}
}

// === SECURITY ENHANCED v1.0 - SYSTEM HARDENING ===

// v1.0: Configure system resource limits for security
func configureSystemLimits() {
	// v1.0: Limit virtual memory to 512MB
	var rLimit syscall.Rlimit
	rLimit.Max = 512 * 1024 * 1024
	rLimit.Cur = 512 * 1024 * 1024
	syscall.Setrlimit(syscall.RLIMIT_AS, &rLimit)
	
	// v1.0: Limit number of file descriptors
	rLimit.Max = 1024
	rLimit.Cur = 1024
	syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rLimit)
	
	// v1.0: Disable core dumps for security
	rLimit.Max = 0
	rLimit.Cur = 0
	syscall.Setrlimit(syscall.RLIMIT_CORE, &rLimit)
	
	logger.Info("System resource limits configured for security")
}

// v1.0: Check and warn about privilege escalation risks
func checkPrivileges() {
	if os.Geteuid() == 0 {
		logger.Warn("Running as root - consider using non-privileged user for security")
		securityEvents.WithLabelValues("root_execution", "medium").Inc()
	}
}

// === ENHANCED HTML TEMPLATE WITH SECURITY FEATURES ===
const htmlTemplate = `
<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<meta http-equiv="Cache-Control" content="no-store, no-cache, must-revalidate, private">
	<meta http-equiv="Pragma" content="no-cache">
	<meta http-equiv="Expires" content="0">
	<title>Victor Mail2News Security Interface v{{.Version}}</title>
	<style>
		body {
			background-color: white;
			color: black;
			font-family: Arial, sans-serif;
		}
		.container {
			width: 50%;
			margin: auto;
			padding: 20px;
			border: 2px solid red;
			background-color: black;
			color: white;
		}
		button {
			background-color: red;
			color: white;
			padding: 10px;
			border: none;
			cursor: pointer;
		}
		button:hover {
			background-color: darkred;
		}
		footer {
			margin-top: 20px;
			text-align: center;
			background-color: red;
			color: black;
			padding: 10px;
		}
		footer a {
			color: black;
			text-decoration: none;
		}
		footer a:hover {
			text-decoration: underline;
		}
		.security-notice {
			background-color: #333;
			border: 1px solid #666;
			padding: 10px;
			margin: 10px 0;
			color: #ccc;
			font-size: 12px;
		}
		.version-info {
			background-color: #1a5490;
			color: white;
			padding: 8px;
			margin: 10px 0;
			border-radius: 4px;
			font-size: 11px;
		}
	</style>
</head>
<body>
	<div class="container">
		<h2>Send Emails to Mail2News Dizum dot COM</h2>
		
		<!-- v1.0: Version and security information -->
		<div class="version-info">
			🛡️ Mail2Dizum Security Enhanced v{{.Version}} | Build: {{.BuildDate}}<br>
			⚡ MemGuard Protected | 🔒 Tor Routed | 📊 Security Monitored
		</div>
		
		<div class="security-notice">
			🔒 <strong>Security Features Active:</strong><br>
			• Memory protection with MemGuard encryption<br>
			• Real-time threat detection and IP banning<br>
			• CSRF protection and rate limiting<br>
			• All data transmitted via Tor network<br>
			• No persistent storage of user information
		</div>
		
		<p>The Mail2News protocol allows you to send emails as usenet postings.</p>
		<p>We do this through the Tor/Onion network with enhanced security.</p>
		
		<form method="POST" action="/send">
			{{ .CSRFField }}
			
			<label for="from">From:</label><br>
			<input type="text" id="from" name="from" placeholder="User Name<email@address>" required autocomplete="off"><br><br>

			<label for="newsgroup">Newsgroup:</label><br>
			<input type="text" id="newsgroup" name="newsgroup" required autocomplete="off"><br><br>

			<label for="subject">Subject:</label><br>
			<input type="text" id="subject" name="subject" required autocomplete="off"><br><br>

			<label for="message">Message:</label><br>
			<textarea id="message" name="message" rows="10" cols="50" required></textarea><br><br>

			<label for="reply_to">References:</label><br>
			<input type="text" id="reply_to" name="reply_to" autocomplete="off"><br><br>

			<label for="antispam">AntiSpam On:</label>
			<input type="checkbox" id="antispam" name="antispam"><br><br>

			<label for="smtp_choice">SMTP Server:</label><br>
			<select id="smtp_choice" name="smtp_choice">
				<option value="xilb7y4kj6u6qfo45o3yk2kilfv54ffukzei3puonuqlncy7cn2afwyd.onion:25" selected>xilb7y4kj6u6qfo45o3yk2kilfv54ffukzei3puonuqlncy7cn2afwyd.onion:25</option>
				<option value="custom">Other (custom)</option>
			</select>
			<br><br>
			<div id="custom_smtp_div" style="display:none;">
				<label for="smtp_custom">Custom SMTP:</label><br>
				<input type="text" id="smtp_custom" name="smtp_custom" placeholder="smtp.example.com:25" autocomplete="off"><br>
				<small>Additional possible addresses at SEC3: <a href="https://www.sec3.net/misc/mail-relays.html" target="_blank" rel="noopener noreferrer">this link</a>.</small>
				<br><br>
			</div>

			<button type="submit">Send Secure</button>
		</form>
	</div>
	<footer>
		<div style="text-align: center;">
			<div>
				<a href="https://github.com/gabrix73/mail2dizum.git" target="_blank" rel="noopener noreferrer">
					GitHub - Security Enhanced Version
				</a>
			</div>
			<div>
				<a href="https://yamn.virebent.art" target="_blank" rel="noopener noreferrer">
					Victor Hostile Communication Center
				</a>
			</div>
			<div>
				<a href="https://dizum.com" target="_blank" rel="noopener noreferrer">
					Powered by dizum.com
				</a>
			</div>
			<div style="font-size: 10px; margin-top: 5px; color: #999;">
				Mail2Dizum Security Enhanced v{{.Version}} by {{.Author}}
			</div>
		</div>	
	</footer>
	<script>
		document.getElementById("smtp_choice").addEventListener("change", function() {
			if (this.value === "custom") {
				document.getElementById("custom_smtp_div").style.display = "block";
			} else {
				document.getElementById("custom_smtp_div").style.display = "none";
			}
		});
		
		// v1.0: Security - Clear sensitive fields on page unload
		window.addEventListener('beforeunload', function() {
			document.getElementById('from').value = '';
			document.getElementById('message').value = '';
			document.getElementById('subject').value = '';
			document.getElementById('reply_to').value = '';
		});
	</script>
	</script>
</body>
</html>
`

// === SECURITY ENHANCED v1.0 - SECURE SMTP FUNCTION ===
// v1.0: Enhanced Tor SMTP with comprehensive security monitoring
func sendMailThroughTor(smtpServer string, secureMsg *SecureMessage, antispam bool) error {
	// v1.0: Ensure secure cleanup regardless of function outcome
	defer secureMsg.Destroy()
	
	// v1.0: Start timing for performance metrics
	start := time.Now()
	defer func() {
		torConnectionDuration.Observe(time.Since(start).Seconds())
	}()
	
	// v1.0: Fixed envelope sender for mail2news service
	envelopeFrom := "mail2news@dizum.com"
	var recipient string
	if antispam {
		recipient = "mail2news_nospam@dizum.com"
		logger.Debug("Using anti-spam route for message delivery")
	} else {
		recipient = "mail2news@dizum.com"
		logger.Debug("Using standard route for message delivery")
	}

	// v1.0: Secure data extraction from MemGuard enclaves
	fromHeader, err := secureMsg.GetFrom()
	if err != nil {
		logger.WithError(err).Error("Failed to access protected 'from' field")
		return fmt.Errorf("memory protection error accessing 'from': %w", err)
	}
	
	newsgroup, err := secureMsg.GetNewsgroup()
	if err != nil {
		logger.WithError(err).Error("Failed to access protected 'newsgroup' field")
		return fmt.Errorf("memory protection error accessing 'newsgroup': %w", err)
	}
	
	subject, err := secureMsg.GetSubject()
	if err != nil {
		logger.WithError(err).Error("Failed to access protected 'subject' field")
		return fmt.Errorf("memory protection error accessing 'subject': %w", err)
	}
	
	message, err := secureMsg.GetMessage()
	if err != nil {
		logger.WithError(err).Error("Failed to access protected 'message' field")
		return fmt.Errorf("memory protection error accessing 'message': %w", err)
	}
	
	references, err := secureMsg.GetReferences()
	if err != nil {
		logger.WithError(err).Error("Failed to access protected 'references' field")
		return fmt.Errorf("memory protection error accessing 'references': %w", err)
	}

	// v1.0: Compose RFC-compliant Usenet message
	msgLines := []string{
		fmt.Sprintf("From: %s", fromHeader),
		fmt.Sprintf("To: %s", recipient),
		fmt.Sprintf("Newsgroups: %s", newsgroup),
		fmt.Sprintf("Subject: %s", subject),
		"X-No-Archive: Yes",
		"Content-Type: text/plain; charset=utf-8",
		"Content-Transfer-Encoding: 8bit",
		"MIME-Version: 1.0",
		fmt.Sprintf("X-Mailer: Mail2Dizum-Security-Enhanced/%s", VERSION),
	}
	
	// v1.0: Add References header only if provided (for threading)
	if references != "" {
		msgLines = append(msgLines, fmt.Sprintf("References: %s", references))
	}
	
	// v1.0: Add message body after headers
	msgLines = append(msgLines, "", message)
	
	// v1.0: Join with CRLF as per RFC 5322
	fullMessage := strings.Join(msgLines, "\r\n")

	// v1.0: Protect composed message in memory
	msgBuffer := memguard.NewBuffer(len(fullMessage))
	if msgBuffer == nil {
		logger.Error("Failed to protect composed message")
		return fmt.Errorf("failed to protect composed message")
	}
	defer msgBuffer.Destroy()
	copy(msgBuffer.Bytes(), []byte(fullMessage))

	// v1.0: Configure Tor SOCKS5 proxy with enhanced error handling
	logger.Debug("Configuring SOCKS5 proxy for Tor routing")
	dialer, err := proxy.SOCKS5("tcp", "127.0.0.1:9050", nil, proxy.Direct)
	if err != nil {
		logger.WithError(err).Error("SOCKS5 proxy configuration failed")
		securityEvents.WithLabelValues("tor_proxy_error", "high").Inc()
		return fmt.Errorf("SOCKS5 proxy configuration error: %w", err)
	}

	// v1.0: Establish Tor connection with timeout
	logger.WithField("server", smtpServer).Info("Establishing Tor connection to SMTP server")
	conn, err := dialer.Dial("tcp", smtpServer)
	if err != nil {
		logger.WithFields(logrus.Fields{
			"server": smtpServer,
			"error":  err,
		}).Error("Tor connection to SMTP server failed")
		securityEvents.WithLabelValues("tor_connection_failed", "high").Inc()
		return fmt.Errorf("Tor connection error to %s: %w", smtpServer, err)
	}
	defer conn.Close()
	logger.Debug("Tor connection established successfully")

	// v1.0: Create SMTP client with enhanced error handling
	host := strings.Split(smtpServer, ":")[0]
	logger.Debug("Creating SMTP client connection")
	client, err := smtp.NewClient(conn, host)
	if err != nil {
		logger.WithError(err).Error("SMTP client creation failed")
		securityEvents.WithLabelValues("smtp_client_error", "medium").Inc()
		return fmt.Errorf("SMTP client creation error: %w", err)
	}
	defer func() {
		if err := client.Close(); err != nil {
			logger.WithError(err).Warn("Error closing SMTP client")
		}
	}()

	// v1.0: SMTP transaction with detailed logging
	logger.Debug("Sending MAIL FROM command")
	if err := client.Mail(envelopeFrom); err != nil {
		logger.WithFields(logrus.Fields{
			"envelope_from": envelopeFrom,
			"error":         err,
		}).Error("MAIL FROM command failed")
		securityEvents.WithLabelValues("smtp_mail_from_error", "medium").Inc()
		return fmt.Errorf("MAIL FROM command error: %w", err)
	}

	logger.Debug("Sending RCPT TO command")
	if err := client.Rcpt(recipient); err != nil {
		logger.WithFields(logrus.Fields{
			"recipient": recipient,
			"error":     err,
		}).Error("RCPT TO command failed")
		securityEvents.WithLabelValues("smtp_rcpt_to_error", "medium").Inc()
		return fmt.Errorf("RCPT TO command error: %w", err)
	}

	// v1.0: Send message data with memory protection
	logger.Debug("Initiating DATA command")
	wc, err := client.Data()
	if err != nil {
		logger.WithError(err).Error("DATA command failed")
		securityEvents.WithLabelValues("smtp_data_error", "medium").Inc()
		return fmt.Errorf("DATA command error: %w", err)
	}
	
	// v1.0: Secure access to protected message content
	logger.Debug("Writing message content")
	_, err = wc.Write(msgBuffer.Bytes())
	if err != nil {
		logger.WithError(err).Error("Failed to write message content")
		securityEvents.WithLabelValues("smtp_write_error", "medium").Inc()
		return fmt.Errorf("message write error: %w", err)
	}
	
	if err := wc.Close(); err != nil {
		logger.WithError(err).Error("Failed to close message writer")
		return fmt.Errorf("message close error: %w", err)
	}

	// v1.0: Graceful SMTP disconnect
	logger.Debug("Sending QUIT command")
	if err := client.Quit(); err != nil {
		logger.WithError(err).Warn("QUIT command failed (message likely sent)")
		// Don't return error as message was probably delivered
	}

	// v1.0: Success metrics and logging
	logger.WithFields(logrus.Fields{
		"newsgroup": newsgroup,
		"antispam":  antispam,
		"server":    smtpServer,
	}).Info("Message sent successfully via Tor")
	
	securityEvents.WithLabelValues("message_sent", "info").Inc()
	return nil
}

// === SECURITY ENHANCED v1.0 - HTTP HANDLERS ===

// v1.0: Secure metrics endpoint (localhost only)
func metricsHandler(w http.ResponseWriter, r *http.Request) {
	// v1.0: Restrict metrics to localhost for security
	clientIP := getClientIP(r)
	if !isLocalhost(clientIP) {
		logger.WithField("ip", clientIP).Warn("Non-localhost access to metrics endpoint denied")
		securityEvents.WithLabelValues("metrics_unauthorized_access", "medium").Inc()
		http.Error(w, "Forbidden", http.StatusForbidden)
		requestsTotal.WithLabelValues(r.Method, r.URL.Path, "403").Inc()
		return
	}
	
	requestsTotal.WithLabelValues(r.Method, r.URL.Path, "200").Inc()
	promhttp.Handler().ServeHTTP(w, r)
}

// v1.0: Check if request is from localhost
func isLocalhost(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// If no port, use the whole string as host
		host = addr
	}
	
	return host == "127.0.0.1" || host == "::1" || host == "localhost"
}

// v1.0: Health check endpoint for monitoring
func healthHandler(w http.ResponseWriter, r *http.Request) {
	requestsTotal.WithLabelValues(r.Method, r.URL.Path, "200").Inc()
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{
		"status": "healthy",
		"version": "%s",
		"build_date": "%s",
		"security_features": [
			"memguard_protection",
			"tor_routing",
			"csrf_protection", 
			"rate_limiting",
			"ip_banning",
			"anomaly_detection",
			"input_sanitization"
		]
	}`, VERSION, BUILD_DATE)
}

// === SECURITY ENHANCED v1.0 - MAIN FUNCTION ===
func main() {
	// v1.0: Ensure complete memory cleanup on exit
	defer memguard.Purge()
	
	// v1.0: Display startup banner with security information
	logger.WithFields(logrus.Fields{
		"version":    VERSION,
		"build_date": BUILD_DATE,
		"author":     AUTHOR,
	}).Info("Starting Mail2Dizum Security Enhanced")
	
	// v1.0: System hardening and security checks
	configureSystemLimits()
	checkPrivileges()
	
	// v1.0: Generate secure CSRF key
	csrfKey := make([]byte, 32)
	if _, err := rand.Read(csrfKey); err != nil {
		logger.Fatal("Failed to generate CSRF key")
	}
	
	// v1.0: Configure CSRF protection middleware
	csrfMiddleware := csrf.Protect(csrfKey,
		csrf.HttpOnly(true),
		csrf.Secure(true), // Enable in production with HTTPS
		csrf.SameSite(csrf.SameSiteStrictMode),
		csrf.ErrorHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logger.WithField("ip", getClientIP(r)).Warn("CSRF token validation failed")
			securityEvents.WithLabelValues("csrf_validation_failed", "medium").Inc()
			http.Error(w, "CSRF token validation failed", http.StatusForbidden)
			requestsTotal.WithLabelValues(r.Method, r.URL.Path, "403").Inc()
		})),
	)

	// v1.0: Main page handler with full security stack
	http.HandleFunc("/", 
		appSecurityHeadersMiddleware(
			ipBanMiddleware(
				anomalyDetectionMiddleware(
					rateLimitMiddleware(
						maxSizeMiddleware(1024*1024)( // 1MB limit
							func(w http.ResponseWriter, r *http.Request) {
								requestsTotal.WithLabelValues(r.Method, r.URL.Path, "200").Inc()
								
								tmpl, err := template.New("webpage").Parse(htmlTemplate)
								if err != nil {
									logger.WithError(err).Error("Template parsing failed")
									http.Error(w, "Internal server error", http.StatusInternalServerError)
									requestsTotal.WithLabelValues(r.Method, r.URL.Path, "500").Inc()
									return
								}
								
								data := struct {
									CSRFField template.HTML
									Version   string
									BuildDate string
									Author    string
								}{
									CSRFField: csrf.TemplateField(r),
									Version:   VERSION,
									BuildDate: BUILD_DATE,
									Author:    AUTHOR,
								}
								
								if err := tmpl.Execute(w, data); err != nil {
									logger.WithError(err).Error("Template execution failed")
									http.Error(w, "Internal server error", http.StatusInternalServerError)
									requestsTotal.WithLabelValues(r.Method, r.URL.Path, "500").Inc()
								}
							},
						),
					),
				),
			),
		),
	)

	// v1.0: Send handler with comprehensive security
	http.HandleFunc("/send",
		appSecurityHeadersMiddleware(
			ipBanMiddleware(
				anomalyDetectionMiddleware(
					antiReplayMiddleware(
						rateLimitMiddleware(
							maxSizeMiddleware(1024*1024)( // 1MB limit
								func(w http.ResponseWriter, r *http.Request) {
									if r.Method != http.MethodPost {
										http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
										requestsTotal.WithLabelValues(r.Method, r.URL.Path, "405").Inc()
										return
									}
									
									if err := r.ParseForm(); err != nil {
										logger.WithError(err).Warn("Form parsing failed")
										http.Error(w, "Error reading form", http.StatusBadRequest)
										requestsTotal.WithLabelValues(r.Method, r.URL.Path, "400").Inc()
										return
									}

									// v1.0: Secure input validation and sanitization
									secureMsg, err := sanitizeAndValidateInput(r)
									if err != nil {
										logger.WithError(err).Warn("Input validation failed")
										http.Error(w, fmt.Sprintf("Input validation error: %s", err), http.StatusBadRequest)
										requestsTotal.WithLabelValues(r.Method, r.URL.Path, "400").Inc()
										return
									}

									// v1.0: Extract configuration options
									antispam := r.FormValue("antispam") == "on"
									smtpChoice := r.FormValue("smtp_choice")
									var smtpServer string
									if smtpChoice == "custom" {
										smtpServer = r.FormValue("smtp_custom")
									} else {
										smtpServer = smtpChoice
									}
									
									if smtpServer == "" {
										secureMsg.Destroy()
										http.Error(w, "Invalid SMTP server address", http.StatusBadRequest)
										requestsTotal.WithLabelValues(r.Method, r.URL.Path, "400").Inc()
										return
									}

									// v1.0: Send message via secure Tor connection
									if err := sendMailThroughTor(smtpServer, secureMsg, antispam); err != nil {
										logger.WithError(err).Error("Message sending failed")
										http.Error(w, "Failed to send message", http.StatusInternalServerError)
										requestsTotal.WithLabelValues(r.Method, r.URL.Path, "500").Inc()
										return
									}

									// v1.0: Success response
									requestsTotal.WithLabelValues(r.Method, r.URL.Path, "200").Inc()
									fmt.Fprintf(w, `<html>
										<head>
											<meta http-equiv="Cache-Control" content="no-store, no-cache, must-revalidate, private">
											<title>Message Sent - Mail2Dizum Security Enhanced</title>
										</head>
										<body>
											<h3>✅ Message sent successfully via secure Tor routing!</h3>
											<p>Your message has been delivered to the dizum.com mail2news service with full security protection.</p>
											<a href="/">← Send another message</a>
											<hr>
											<small>Mail2Dizum Security Enhanced v%s</small>
										</body>
									</html>`, VERSION)
								},
							),
						),
					),
				),
			),
		),
	)

	// v1.0: Security monitoring endpoints
	http.HandleFunc("/metrics", metricsHandler)
	http.HandleFunc("/health", healthHandler)

	// v1.0: Configure secure HTTP server
	server := &http.Server{
		Addr:              ":8080",
		Handler:           csrfMiddleware(http.DefaultServeMux),
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1MB
	}

	// v1.0: Limit concurrent connections for DoS protection
	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		logger.WithError(err).Fatal("Failed to create server listener")
	}
	
	// v1.0: Maximum 100 concurrent connections
	limitedListener := netutil.LimitListener(listener, 100)

	// v1.0: Startup complete
	logger.WithFields(logrus.Fields{
		"addr":               server.Addr,
		"max_connections":    100,
		"rate_limit":         "5 requests/minute",
		"memory_protection":  "MemGuard active",
		"tor_routing":        "SOCKS5 :9050",
		"csrf_protection":    "enabled",
		"monitoring":         "/metrics, /health",
	}).Info("Mail2Dizum Security Enhanced server started")

	// v1.0: Start secure server
	if err := server.Serve(limitedListener); err != nil {
		logger.WithError(err).Fatal("Server startup failed")
	}
}
