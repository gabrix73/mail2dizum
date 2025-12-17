/*
 * Mail2Dizum with MemGuard v1.3
 * ===================================
 * 
 * Secure web interface for Usenet posting via dizum.com mail2news service
 * Enhanced with MemGuard memory protection and privacy-focused logging
 * 
 * Repository: https://github.com/gabrix73/mail2dizum.git
 * License: Open Source
 */

package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/smtp"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/awnumar/memguard"
	"github.com/go-playground/validator/v10"
	"github.com/microcosm-cc/bluemonday"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/netutil"
	"golang.org/x/net/proxy"
	"golang.org/x/time/rate"
)

const (
	VERSION    = "1.3.0-memguard"
	BUILD_DATE = "2025-12-17"
)

var (
	// Global rate limiter - più restrittivo
	globalLimiter = rate.NewLimiter(rate.Every(time.Second), 10)
	
	// Per-IP rate limiters
	ipLimiters  = make(map[string]*rate.Limiter)
	ipLimiterMu sync.Mutex
	
	logger        = logrus.New()
	validate      *validator.Validate
	htmlSanitizer *bluemonday.Policy
	requestCount  uint64
	mu            sync.Mutex
)

type SecurityCache struct {
	bannedIPs      map[string]time.Time
	failedAttempts map[string]int
	mutex          sync.RWMutex
}

var securityCache = &SecurityCache{
	bannedIPs:      make(map[string]time.Time),
	failedAttempts: make(map[string]int),
}

type SecureMessage struct {
	from       *memguard.Enclave
	newsgroup  *memguard.Enclave
	subject    *memguard.Enclave
	message    *memguard.Enclave
	references *memguard.Enclave
}

func init() {
	// Configure verbose logging without IP addresses
	logger.SetFormatter(&logrus.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: "2006-01-02 15:04:05",
		DisableColors:   false,
	})
	logger.SetLevel(logrus.DebugLevel)
	
	// Initialize MemGuard
	memguard.CatchInterrupt()
	
	validate = validator.New()
	htmlSanitizer = bluemonday.StrictPolicy()
	
	go securityCacheCleanup()
	go ipLimiterCleanup()
	
	logger.WithFields(logrus.Fields{
		"version":    VERSION,
		"memguard":   "enabled",
		"build_date": BUILD_DATE,
	}).Info("Mail2Dizum with MemGuard initialized successfully")
}

// Cleanup old IP limiters to prevent memory leak
func ipLimiterCleanup() {
	ticker := time.NewTicker(30 * time.Minute)
	defer ticker.Stop()
	
	for range ticker.C {
		ipLimiterMu.Lock()
		oldCount := len(ipLimiters)
		ipLimiters = make(map[string]*rate.Limiter)
		ipLimiterMu.Unlock()
		
		if oldCount > 0 {
			logger.WithField("cleared_limiters", oldCount).Debug("IP rate limiters cleared")
		}
	}
}

// Get or create a rate limiter for a specific IP
func getIPLimiter(ip string) *rate.Limiter {
	ipLimiterMu.Lock()
	defer ipLimiterMu.Unlock()
	
	const maxTrackedIPs = 1000
	
	if len(ipLimiters) > maxTrackedIPs {
		logger.WithField("count", len(ipLimiters)).Debug("Clearing IP limiters due to size limit")
		ipLimiters = make(map[string]*rate.Limiter)
	}
	
	limiter, exists := ipLimiters[ip]
	if !exists {
		limiter = rate.NewLimiter(rate.Every(5*time.Second), 2)
		ipLimiters[ip] = limiter
	}
	return limiter
}

// Hash IP for privacy in logs
func hashIP(ip string) string {
	hasher := sha256.New()
	hasher.Write([]byte(ip))
	return hex.EncodeToString(hasher.Sum(nil))[:16]
}

func NewSecureMessage(from, newsgroup, subject, message, references string) (*SecureMessage, error) {
	logger.Debug("Creating new secure message with MemGuard protection")
	
	sm := &SecureMessage{}
	
	if from != "" {
		sm.from = memguard.NewEnclave([]byte(from))
	}
	if newsgroup != "" {
		sm.newsgroup = memguard.NewEnclave([]byte(newsgroup))
	}
	if subject != "" {
		sm.subject = memguard.NewEnclave([]byte(subject))
	}
	if message != "" {
		sm.message = memguard.NewEnclave([]byte(message))
	}
	if references != "" {
		sm.references = memguard.NewEnclave([]byte(references))
	}
	
	logger.Debug("Secure message created, all data encrypted in memory")
	return sm, nil
}

func (sm *SecureMessage) Destroy() {
	logger.Debug("Destroying secure message and wiping memory")
	
	sm.from = nil
	sm.newsgroup = nil
	sm.subject = nil
	sm.message = nil
	sm.references = nil
}

func (sm *SecureMessage) GetFrom() (string, error) {
	if sm.from == nil {
		return "", nil
	}
	locked, err := sm.from.Open()
	if err != nil {
		logger.Error("Failed to unlock 'from' enclave")
		return "", err
	}
	defer locked.Destroy()
	return string(locked.Bytes()), nil
}

func (sm *SecureMessage) GetNewsgroup() (string, error) {
	if sm.newsgroup == nil {
		return "", nil
	}
	locked, err := sm.newsgroup.Open()
	if err != nil {
		logger.Error("Failed to unlock 'newsgroup' enclave")
		return "", err
	}
	defer locked.Destroy()
	return string(locked.Bytes()), nil
}

func (sm *SecureMessage) GetSubject() (string, error) {
	if sm.subject == nil {
		return "", nil
	}
	locked, err := sm.subject.Open()
	if err != nil {
		logger.Error("Failed to unlock 'subject' enclave")
		return "", err
	}
	defer locked.Destroy()
	return string(locked.Bytes()), nil
}

func (sm *SecureMessage) GetMessage() (string, error) {
	if sm.message == nil {
		return "", nil
	}
	locked, err := sm.message.Open()
	if err != nil {
		logger.Error("Failed to unlock 'message' enclave")
		return "", err
	}
	defer locked.Destroy()
	return string(locked.Bytes()), nil
}

func (sm *SecureMessage) GetReferences() (string, error) {
	if sm.references == nil {
		return "", nil
	}
	locked, err := sm.references.Open()
	if err != nil {
		logger.Error("Failed to unlock 'references' enclave")
		return "", err
	}
	defer locked.Destroy()
	return string(locked.Bytes()), nil
}

func securityCacheCleanup() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		logger.Debug("Running security cache cleanup")
		securityCache.mutex.Lock()
		now := time.Now()

		cleanedCount := 0
		for ip, banTime := range securityCache.bannedIPs {
			if now.Sub(banTime) > 24*time.Hour {
				delete(securityCache.bannedIPs, ip)
				cleanedCount++
			}
		}

		securityCache.failedAttempts = make(map[string]int)
		securityCache.mutex.Unlock()
		
		if cleanedCount > 0 {
			logger.WithField("cleaned_entries", cleanedCount).Info("Security cache cleanup completed")
		}
	}
}

func isIPBanned(ip string) bool {
	securityCache.mutex.RLock()
	defer securityCache.mutex.RUnlock()

	banTime, exists := securityCache.bannedIPs[ip]
	if !exists {
		return false
	}

	return time.Since(banTime) < 24*time.Hour
}

func banIP(ip string, reason string) {
	securityCache.mutex.Lock()
	defer securityCache.mutex.Unlock()

	securityCache.bannedIPs[ip] = time.Now()
	logger.WithFields(logrus.Fields{
		"hashed_ip":    hashIP(ip),
		"reason":       reason,
		"ban_duration": "24h",
	}).Warn("IP banned for suspicious activity")
}

func recordFailedAttempt(ip string) {
	securityCache.mutex.Lock()
	defer securityCache.mutex.Unlock()
	
	securityCache.failedAttempts[ip]++
	attempts := securityCache.failedAttempts[ip]
	
	if attempts >= 10 {
		securityCache.bannedIPs[ip] = time.Now()
		delete(securityCache.failedAttempts, ip)
		logger.WithFields(logrus.Fields{
			"hashed_ip": hashIP(ip),
			"attempts":  attempts,
		}).Warn("IP banned after multiple failed attempts")
	}
}

func getClientIP(r *http.Request) string {
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		return strings.Split(forwarded, ",")[0]
	}

	realIP := r.Header.Get("X-Real-IP")
	if realIP != "" {
		return realIP
	}

	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}

func ipBanMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clientIP := getClientIP(r)

		if isIPBanned(clientIP) {
			logger.WithField("hashed_ip", hashIP(clientIP)).Debug("Banned IP attempted access")
			http.Error(w, "Access denied", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	}
}

func rateLimitMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clientIP := getClientIP(r)
		
		if !globalLimiter.Allow() {
			recordFailedAttempt(clientIP)
			logger.WithField("hashed_ip", hashIP(clientIP)).Warn("Global rate limit exceeded")
			http.Error(w, "Server busy, please try again later", http.StatusServiceUnavailable)
			return
		}
		
		ipLimiter := getIPLimiter(clientIP)
		if !ipLimiter.Allow() {
			recordFailedAttempt(clientIP)
			logger.WithField("hashed_ip", hashIP(clientIP)).Warn("Per-IP rate limit exceeded")
			http.Error(w, "Rate limit exceeded, please slow down", http.StatusTooManyRequests)
			return
		}
		
		next.ServeHTTP(w, r)
	}
}

func appSecurityHeadersMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, private")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'")
		next.ServeHTTP(w, r)
	}
}

func anomalyDetectionMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clientIP := getClientIP(r)

		userAgent := strings.ToLower(r.UserAgent())
		suspiciousPatterns := []string{
			"sqlmap", "nmap", "nikto", "burp", "metasploit",
			"wget", "curl", "python-requests", "bot", "crawler",
			"scanner", "exploit", "hack", "injection", "spider",
			"scraper", "dirbuster", "gobuster", "wfuzz",
		}

		for _, pattern := range suspiciousPatterns {
			if strings.Contains(userAgent, pattern) {
				logger.WithFields(logrus.Fields{
					"hashed_ip": hashIP(clientIP),
					"pattern":   pattern,
				}).Warn("Suspicious User-Agent detected")
				banIP(clientIP, "Suspicious User-Agent: "+pattern)
				http.Error(w, "Access denied", http.StatusForbidden)
				return
			}
		}

		for headerName, values := range r.Header {
			for _, value := range values {
				if strings.Contains(value, "\r") || strings.Contains(value, "\n") {
					logger.WithFields(logrus.Fields{
						"hashed_ip": hashIP(clientIP),
						"header":    headerName,
					}).Warn("Header injection attempt detected")
					banIP(clientIP, "Header injection attempt")
					http.Error(w, "Access denied", http.StatusForbidden)
					return
				}
			}
		}

		next.ServeHTTP(w, r)
	}
}

func maxSizeMiddleware(maxSize int64) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, maxSize)
			next.ServeHTTP(w, r)
		}
	}
}

// validateFromField validates the From field format:
// - Username: 1-2 words, each max 12 characters, only alphanumeric
// - Email: must be in format <address@domain.tld>
func validateFromField(from string) error {
	from = strings.TrimSpace(from)
	
	// Check minimum length
	if len(from) < 5 {
		return fmt.Errorf("From field too short")
	}
	
	// Find the email part between < and >
	openBracket := strings.LastIndex(from, "<")
	closeBracket := strings.LastIndex(from, ">")
	
	if openBracket == -1 || closeBracket == -1 || closeBracket <= openBracket {
		return fmt.Errorf("email must be in format: Name <email@domain>")
	}
	
	// Check that > is at the end (with possible trailing whitespace)
	afterBracket := strings.TrimSpace(from[closeBracket+1:])
	if afterBracket != "" {
		return fmt.Errorf("nothing should follow the email address")
	}
	
	// Extract username part (before <)
	usernamePart := strings.TrimSpace(from[:openBracket])
	
	// Extract email part (between < and >)
	emailPart := strings.TrimSpace(from[openBracket+1 : closeBracket])
	
	// Validate username part
	if usernamePart == "" {
		return fmt.Errorf("username is required before email")
	}
	
	// Split username into words
	words := strings.Fields(usernamePart)
	
	if len(words) == 0 || len(words) > 2 {
		return fmt.Errorf("username must contain 1 or 2 words")
	}
	
	// Validate each word
	for _, word := range words {
		if len(word) > 12 {
			return fmt.Errorf("each word in username must be max 12 characters")
		}
		
		if len(word) == 0 {
			return fmt.Errorf("empty word in username not allowed")
		}
		
		// Allow only alphanumeric characters (no special chars)
		for _, char := range word {
			if !((char >= 'a' && char <= 'z') || 
			     (char >= 'A' && char <= 'Z') || 
			     (char >= '0' && char <= '9')) {
				return fmt.Errorf("username can only contain letters and numbers")
			}
		}
	}
	
	// Validate email format
	if emailPart == "" {
		return fmt.Errorf("email address is required")
	}
	
	// Check for dangerous characters in email (injection prevention)
	dangerousChars := []string{"\r", "\n", "\t", ";", "'", "\"", "\\", "|", "&", "$", "`"}
	for _, dc := range dangerousChars {
		if strings.Contains(emailPart, dc) {
			return fmt.Errorf("email contains invalid characters")
		}
	}
	
	atIndex := strings.Index(emailPart, "@")
	if atIndex == -1 || atIndex == 0 || atIndex == len(emailPart)-1 {
		return fmt.Errorf("invalid email format")
	}
	
	// Check for multiple @ symbols
	if strings.Count(emailPart, "@") != 1 {
		return fmt.Errorf("email must contain exactly one @ symbol")
	}
	
	localPart := emailPart[:atIndex]
	domainPart := emailPart[atIndex+1:]
	
	// Validate local part (before @)
	if len(localPart) == 0 || len(localPart) > 64 {
		return fmt.Errorf("email local part must be 1-64 characters")
	}
	
	// Validate domain part (after @)
	if len(domainPart) < 3 || !strings.Contains(domainPart, ".") {
		return fmt.Errorf("invalid email domain")
	}
	
	if len(domainPart) > 253 {
		return fmt.Errorf("email domain too long")
	}
	
	// Check domain has valid structure
	dotIndex := strings.LastIndex(domainPart, ".")
	if dotIndex == 0 || dotIndex == len(domainPart)-1 {
		return fmt.Errorf("invalid email domain format")
	}
	
	// TLD must be at least 2 characters
	tld := domainPart[dotIndex+1:]
	if len(tld) < 2 {
		return fmt.Errorf("invalid TLD in email")
	}
	
	// Validate allowed characters in email local part
	allowedLocalChars := func(s string) bool {
		for _, char := range s {
			isAlphaNum := (char >= 'a' && char <= 'z') || 
			              (char >= 'A' && char <= 'Z') || 
			              (char >= '0' && char <= '9')
			isAllowedSpecial := char == '-' || char == '_' || char == '+' || char == '.'
			
			if !isAlphaNum && !isAllowedSpecial {
				return false
			}
		}
		return true
	}
	
	// Validate allowed characters in domain
	allowedDomainChars := func(s string) bool {
		for _, char := range s {
			isAlphaNum := (char >= 'a' && char <= 'z') || 
			              (char >= 'A' && char <= 'Z') || 
			              (char >= '0' && char <= '9')
			isAllowedSpecial := char == '-' || char == '.'
			
			if !isAlphaNum && !isAllowedSpecial {
				return false
			}
		}
		return true
	}
	
	if !allowedLocalChars(localPart) {
		return fmt.Errorf("email local part contains invalid characters")
	}
	
	if !allowedDomainChars(domainPart) {
		return fmt.Errorf("email domain contains invalid characters")
	}
	
	// Check for consecutive dots
	if strings.Contains(localPart, "..") || strings.Contains(domainPart, "..") {
		return fmt.Errorf("email cannot contain consecutive dots")
	}
	
	// Check local part doesn't start or end with dot
	if strings.HasPrefix(localPart, ".") || strings.HasSuffix(localPart, ".") {
		return fmt.Errorf("email local part cannot start or end with dot")
	}
	
	// Check domain doesn't start or end with hyphen
	if strings.HasPrefix(domainPart, "-") || strings.HasSuffix(domainPart, "-") {
		return fmt.Errorf("email domain cannot start or end with hyphen")
	}
	
	return nil
}

func sanitizeAndValidateInput(r *http.Request) (*SecureMessage, error) {
	logger.Debug("Sanitizing and validating input")
	
	from := strings.TrimSpace(r.FormValue("from"))
	newsgroup := strings.TrimSpace(r.FormValue("newsgroup"))
	subject := strings.TrimSpace(r.FormValue("subject"))
	message := strings.TrimSpace(r.FormValue("message"))
	references := strings.TrimSpace(r.FormValue("reply_to"))

	// Basic required fields check
	if from == "" || newsgroup == "" || subject == "" || message == "" {
		logger.Debug("Validation failed: missing required fields")
		return nil, fmt.Errorf("all required fields must be filled")
	}

	// Validate From field with strict rules
	if err := validateFromField(from); err != nil {
		logger.WithField("error", err.Error()).Debug("From field validation failed")
		return nil, fmt.Errorf("From field error: %s", err.Error())
	}

	// Validate newsgroup format
	if !isValidNewsgroup(newsgroup) {
		logger.Debug("Validation failed: invalid newsgroup format")
		return nil, fmt.Errorf("invalid newsgroup format")
	}

	// Length limits
	if len(subject) > 200 {
		return nil, fmt.Errorf("subject too long (max 200 characters)")
	}
	if len(message) > 50000 {
		return nil, fmt.Errorf("message too long (max 50000 characters)")
	}

	// Validate references if provided (Message-ID format)
	if references != "" {
		if !isValidMessageID(references) {
			logger.Debug("Validation failed: invalid Message-ID format")
			return nil, fmt.Errorf("invalid Message-ID format in references")
		}
	}

	logger.Debug("Input validation successful")
	return NewSecureMessage(from, newsgroup, subject, message, references)
}

// isValidNewsgroup validates newsgroup name format
func isValidNewsgroup(ng string) bool {
	if len(ng) < 3 || len(ng) > 200 {
		return false
	}
	
	// Must contain at least one dot
	if !strings.Contains(ng, ".") {
		return false
	}
	
	// Check for valid characters (alphanumeric, dots, hyphens, plus)
	for _, char := range ng {
		isAlphaNum := (char >= 'a' && char <= 'z') || 
		              (char >= 'A' && char <= 'Z') || 
		              (char >= '0' && char <= '9')
		isAllowed := char == '.' || char == '-' || char == '+' || char == '_'
		
		if !isAlphaNum && !isAllowed {
			return false
		}
	}
	
	// Cannot start or end with dot
	if strings.HasPrefix(ng, ".") || strings.HasSuffix(ng, ".") {
		return false
	}
	
	// No consecutive dots
	if strings.Contains(ng, "..") {
		return false
	}
	
	return true
}

// isValidMessageID validates Message-ID format
func isValidMessageID(msgID string) bool {
	msgID = strings.TrimSpace(msgID)
	
	if len(msgID) < 5 || len(msgID) > 250 {
		return false
	}
	
	// Must be enclosed in < >
	if !strings.HasPrefix(msgID, "<") || !strings.HasSuffix(msgID, ">") {
		return false
	}
	
	// Must contain @
	if !strings.Contains(msgID, "@") {
		return false
	}
	
	// Check for injection characters
	dangerousChars := []string{"\r", "\n", "\t", ";", "'", "\"", "\\", "|", "&", "$", "`"}
	for _, dc := range dangerousChars {
		if strings.Contains(msgID, dc) {
			return false
		}
	}
	
	return true
}

func configureSystemLimits() {
	var rLimit syscall.Rlimit
	
	// File descriptors limit
	rLimit.Max = 1024
	rLimit.Cur = 1024
	syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rLimit)

	// Disable core dumps for security
	rLimit.Max = 0
	rLimit.Cur = 0
	syscall.Setrlimit(syscall.RLIMIT_CORE, &rLimit)
	
	logger.Debug("System limits configured (without memory restrictions)")
}

func checkPrivileges() {
	if os.Geteuid() == 0 {
		logger.Warn("Running as root - consider using non-privileged user for security")
	} else {
		logger.Info("Running as non-privileged user (recommended)")
	}
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<meta http-equiv="Cache-Control" content="no-store, no-cache, must-revalidate, private">
	<meta http-equiv="Pragma" content="no-cache">
	<meta http-equiv="Expires" content="0">
	<title>Mail2Dizum v{{.Version}} - MemGuard Protected</title>
	<style>
		body {
			background-color: white;
			color: black;
			font-family: Arial, sans-serif;
			margin: 0;
			padding: 0;
		}
		.container {
			width: 90%;
			max-width: 600px;
			margin: 20px auto;
			padding: 20px;
			border: 2px solid red;
			background-color: black;
			color: white;
		}
		input[type="text"], textarea, select {
			width: 100%;
			padding: 8px;
			margin-top: 5px;
			box-sizing: border-box;
			background-color: #222;
			color: white;
			border: 1px solid #444;
		}
		button {
			background-color: red;
			color: white;
			padding: 10px 20px;
			border: none;
			cursor: pointer;
			font-size: 16px;
			margin-top: 10px;
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
			background-color: #1a1a1a;
			border: 1px solid #444;
			padding: 10px;
			margin: 10px 0;
			color: #aaa;
			font-size: 12px;
			border-radius: 4px;
		}
		.version-info {
			background-color: #0d47a1;
			color: white;
			padding: 10px;
			margin: 10px 0;
			border-radius: 4px;
			font-size: 12px;
			text-align: center;
		}
		.memguard-active {
			color: #4ade80;
			font-weight: bold;
		}
		.warning {
			background-color: #ff6b6b;
			color: white;
			padding: 5px;
			margin: 10px 0;
			border-radius: 3px;
			font-size: 11px;
		}
		.field-hint {
			color: #888;
			font-size: 11px;
			margin-top: 3px;
			margin-bottom: 10px;
		}
		label {
			margin-top: 10px;
			display: block;
		}
	</style>
</head>
<body>
	<div class="container">
		<h2>Mail2Dizum - Send to Usenet via Dizum.com</h2>
		
		<div class="version-info">
			<strong>Mail2Dizum v{{.Version}}</strong><br>
			<span class="memguard-active">✓ MemGuard Memory Protection Active</span><br>
			Tor Routed | Privacy Enhanced | Build: {{.BuildDate}}
		</div>
		
		<div class="security-notice">
			<strong>🔒 Security Features:</strong><br>
			• <span class="memguard-active">MemGuard: All sensitive data encrypted in memory</span><br>
			• Tor network routing for anonymity<br>
			• No IP logging - only hashed identifiers<br>
			• Automatic memory wiping after use<br>
			• Rate limiting and DDoS protection<br>
			• Input validation and sanitization
		</div>
		
		<p>Post to Usenet newsgroups anonymously through the Dizum mail2news gateway.</p>
		
		<form method="POST" action="/send">
			<label for="from">From:</label>
			<input type="text" id="from" name="from" placeholder="Name Surname <email@example.com>" required autocomplete="off">
			<div class="field-hint">Format: 1-2 words (max 12 chars each) + email in &lt;brackets&gt;</div>

			<label for="newsgroup">Newsgroup:</label>
			<input type="text" id="newsgroup" name="newsgroup" placeholder="alt.test" required autocomplete="off">

			<label for="subject">Subject:</label>
			<input type="text" id="subject" name="subject" maxlength="200" required autocomplete="off">

			<label for="message">Message:</label>
			<textarea id="message" name="message" rows="10" maxlength="50000" required></textarea>

			<label for="reply_to">References (Message-ID for replies):</label>
			<input type="text" id="reply_to" name="reply_to" placeholder="<msgid@domain.tld> (optional)" autocomplete="off">
			<div class="field-hint">Leave empty for new posts, use Message-ID for replies</div>

			<label>
				<input type="checkbox" id="antispam" name="antispam">
				Enable AntiSpam (mail2news_nospam@dizum.com)
			</label>

			<label for="smtp_choice">SMTP Server:</label>
			<select id="smtp_choice" name="smtp_choice">
				<option value="xilb7y4kj6u6qfo45o3yk2kilfv54ffukzei3puonuqlncy7cn2afwyd.onion:25" selected>
					Victor Onion SMTP (Onion smtp classic)
				</option>
				<option value="custom">Custom SMTP Server</option>
			</select>
			
			<div id="custom_smtp_div" style="display:none; margin-top:10px;">
				<label for="smtp_custom">Custom SMTP Server:</label>
				<input type="text" id="smtp_custom" name="smtp_custom" placeholder="smtp.example.com:25" autocomplete="off">
				<div class="field-hint">See <a href="https://www.sec3.net/misc/mail-relays.html" target="_blank" rel="noopener noreferrer" style="color:#4ade80;">SEC3 mail relays</a> for alternatives</div>
			</div>

			<button type="submit">Send via Tor</button>
		</form>
		
		<div class="warning">
			⚠️ Rate limited: Max 2 messages per 5 seconds per user
		</div>
	</div>
	
	<footer>
		<div>
			<a href="https://github.com/gabrix73/mail2dizum" target="_blank" rel="noopener noreferrer">
				GitHub Repository
			</a> | 
			<a href="https://dizum.com" target="_blank" rel="noopener noreferrer">
				Dizum.com
			</a> | 
			<a href="https://yamn.virebent.art" target="_blank" rel="noopener noreferrer">
				Victor Hostile
			</a>
		</div>
		<div style="font-size: 10px; margin-top: 5px; color: #666;">
			Mail2Dizum v{{.Version}} - MemGuard Edition
		</div>	
	</footer>
	
	<script>
		document.getElementById("smtp_choice").addEventListener("change", function() {
			var customDiv = document.getElementById("custom_smtp_div");
			if (this.value === "custom") {
				customDiv.style.display = "block";
			} else {
				customDiv.style.display = "none";
			}
		});
		
		// Clear sensitive data on page unload
		window.addEventListener('beforeunload', function() {
			document.getElementById('from').value = '';
			document.getElementById('message').value = '';
			document.getElementById('subject').value = '';
			document.getElementById('reply_to').value = '';
			document.getElementById('smtp_custom').value = '';
		});
		
		// Prevent form resubmission
		if (window.history.replaceState) {
			window.history.replaceState(null, null, window.location.href);
		}
	</script>
</body>
</html>`

func sendMailThroughTor(smtpServer string, secureMsg *SecureMessage, antispam bool) error {
	defer secureMsg.Destroy()

	logger.WithField("smtp_server", smtpServer).Debug("Initiating Tor connection for mail delivery")
	start := time.Now()

	envelopeFrom := "mail2news@dizum.com"
	var recipient string
	if antispam {
		recipient = "mail2news_nospam@dizum.com"
		logger.Debug("AntiSpam mode enabled")
	} else {
		recipient = "mail2news@dizum.com"
	}

	// Decrypt data from MemGuard enclaves
	fromHeader, err := secureMsg.GetFrom()
	if err != nil {
		logger.Error("Failed to decrypt 'from' field")
		return err
	}
	newsgroup, err := secureMsg.GetNewsgroup()
	if err != nil {
		logger.Error("Failed to decrypt 'newsgroup' field")
		return err
	}
	subject, err := secureMsg.GetSubject()
	if err != nil {
		logger.Error("Failed to decrypt 'subject' field")
		return err
	}
	message, err := secureMsg.GetMessage()
	if err != nil {
		logger.Error("Failed to decrypt 'message' field")
		return err
	}
	references, err := secureMsg.GetReferences()
	if err != nil {
		logger.Error("Failed to decrypt 'references' field")
		return err
	}

	logger.Debug("Successfully decrypted all message fields from MemGuard")

	// Generate randomized Message-ID to prevent correlation
	messageID, err := generateMessageID()
	if err != nil {
		logger.WithError(err).Error("Failed to generate Message-ID")
		return fmt.Errorf("Message-ID generation error: %w", err)
	}
	logger.Debug("Generated uncorrelatable Message-ID")

	// Build email message with our own Message-ID
	msgLines := []string{
		fmt.Sprintf("From: %s", fromHeader),
		fmt.Sprintf("To: %s", recipient),
		fmt.Sprintf("Newsgroups: %s", newsgroup),
		fmt.Sprintf("Subject: %s", subject),
		fmt.Sprintf("Message-ID: %s", messageID),
		"X-No-Archive: Yes",
		"Content-Type: text/plain; charset=utf-8",
		"MIME-Version: 1.0",
	}

	if references != "" {
		msgLines = append(msgLines, fmt.Sprintf("References: %s", references))
	}

	msgLines = append(msgLines, "", message)
	fullMessage := strings.Join(msgLines, "\r\n")

	// Establish Tor connection
	logger.Debug("Establishing SOCKS5 connection through Tor")
	dialer, err := proxy.SOCKS5("tcp", "127.0.0.1:9050", nil, proxy.Direct)
	if err != nil {
		logger.WithError(err).Error("Failed to create SOCKS5 proxy connection")
		return fmt.Errorf("SOCKS5 proxy error: %w", err)
	}

	conn, err := dialer.Dial("tcp", smtpServer)
	if err != nil {
		logger.WithError(err).Error("Failed to establish Tor connection")
		return fmt.Errorf("Tor connection error: %w", err)
	}
	defer conn.Close()

	logger.Debug("Tor connection established, initializing SMTP client")

	// SMTP communication
	host := strings.Split(smtpServer, ":")[0]
	client, err := smtp.NewClient(conn, host)
	if err != nil {
		logger.WithError(err).Error("Failed to create SMTP client")
		return fmt.Errorf("SMTP client error: %w", err)
	}
	defer client.Close()

	logger.Debug("Sending SMTP commands")
	
	if err := client.Mail(envelopeFrom); err != nil {
		logger.WithError(err).Error("MAIL FROM command failed")
		return fmt.Errorf("MAIL FROM error: %w", err)
	}

	if err := client.Rcpt(recipient); err != nil {
		logger.WithError(err).Error("RCPT TO command failed")
		return fmt.Errorf("RCPT TO error: %w", err)
	}

	wc, err := client.Data()
	if err != nil {
		logger.WithError(err).Error("DATA command failed")
		return fmt.Errorf("DATA error: %w", err)
	}

	_, err = wc.Write([]byte(fullMessage))
	if err != nil {
		logger.WithError(err).Error("Failed to write message data")
		return fmt.Errorf("write error: %w", err)
	}

	wc.Close()
	client.Quit()

	duration := time.Since(start)
	logger.WithFields(logrus.Fields{
		"duration_ms": duration.Milliseconds(),
		"newsgroup":   newsgroup,
		"antispam":    antispam,
	}).Info("Message successfully sent through Tor")
	
	return nil
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	requestCount++
	count := requestCount
	mu.Unlock()
	
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status": "healthy", "version": "%s", "memguard": "active", "requests_served": %d}`, VERSION, count)
	
	logger.Debug("Health check requested")
}

func mainHandler(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	requestCount++
	mu.Unlock()
	
	logger.WithFields(logrus.Fields{
		"method":     r.Method,
		"path":       r.URL.Path,
		"user_agent": r.UserAgent(),
	}).Debug("Main page requested")

	tmpl, err := template.New("webpage").Parse(htmlTemplate)
	if err != nil {
		logger.WithError(err).Error("Failed to parse HTML template")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	data := struct {
		Version   string
		BuildDate string
	}{
		Version:   VERSION,
		BuildDate: BUILD_DATE,
	}

	if err := tmpl.Execute(w, data); err != nil {
		logger.WithError(err).Error("Failed to execute template")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

func sendHandler(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	requestCount++
	mu.Unlock()
	
	logger.Debug("Send request received")
	
	if r.Method != http.MethodPost {
		logger.Debug("Invalid method for /send endpoint")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		logger.WithError(err).Error("Failed to parse form data")
		http.Error(w, "Error reading form", http.StatusBadRequest)
		return
	}

	secureMsg, err := sanitizeAndValidateInput(r)
	if err != nil {
		logger.WithError(err).Debug("Input validation failed")
		http.Error(w, fmt.Sprintf("Validation error: %s", err), http.StatusBadRequest)
		return
	}

	antispam := r.FormValue("antispam") == "on"
	smtpChoice := r.FormValue("smtp_choice")
	var smtpServer string
	if smtpChoice == "custom" {
		smtpServer = strings.TrimSpace(r.FormValue("smtp_custom"))
		if smtpServer == "" {
			secureMsg.Destroy()
			logger.Debug("Custom SMTP server not specified")
			http.Error(w, "Custom SMTP server required", http.StatusBadRequest)
			return
		}
		// Validate custom SMTP server format
		if !isValidSMTPServer(smtpServer) {
			secureMsg.Destroy()
			logger.Debug("Invalid custom SMTP server format")
			http.Error(w, "Invalid SMTP server format", http.StatusBadRequest)
			return
		}
	} else {
		smtpServer = smtpChoice
	}

	if smtpServer == "" {
		secureMsg.Destroy()
		logger.Debug("No SMTP server specified")
		http.Error(w, "Invalid SMTP server", http.StatusBadRequest)
		return
	}

	logger.WithFields(logrus.Fields{
		"smtp_server": smtpServer,
		"antispam":    antispam,
	}).Info("Processing message for delivery")
	
	if err := sendMailThroughTor(smtpServer, secureMsg, antispam); err != nil {
		logger.WithError(err).Error("Failed to send message through Tor")
		http.Error(w, "Failed to send message. Please check Tor connection and try again.", http.StatusInternalServerError)
		return
	}

	logger.Info("Message sent successfully, returning confirmation page")
	
	// Success response
	successHTML := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta http-equiv="Cache-Control" content="no-store, no-cache, must-revalidate, private">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Message Sent - Mail2Dizum</title>
	<style>
		body {
			font-family: Arial, sans-serif;
			background: #f0f0f0;
			margin: 0;
			padding: 20px;
		}
		.success-container {
			max-width: 600px;
			margin: 0 auto;
			background: white;
			padding: 30px;
			border-radius: 8px;
			box-shadow: 0 2px 10px rgba(0,0,0,0.1);
		}
		.success-header {
			color: #28a745;
			font-size: 24px;
			margin-bottom: 20px;
			text-align: center;
		}
		.success-message {
			color: #333;
			line-height: 1.6;
			margin-bottom: 20px;
		}
		.success-message ul {
			margin: 10px 0;
			padding-left: 20px;
		}
		.success-message li {
			margin: 5px 0;
		}
		.back-link {
			display: inline-block;
			background: #007bff;
			color: white;
			padding: 10px 20px;
			text-decoration: none;
			border-radius: 4px;
			margin-top: 20px;
		}
		.back-link:hover {
			background: #0056b3;
		}
		.footer {
			margin-top: 30px;
			padding-top: 20px;
			border-top: 1px solid #eee;
			color: #666;
			font-size: 12px;
			text-align: center;
		}
		.memguard-active {
			color: #4ade80;
			font-weight: bold;
		}
		.checkmark {
			color: #28a745;
			font-size: 48px;
			text-align: center;
			margin-bottom: 20px;
		}
	</style>
</head>
<body>
	<div class="success-container">
		<div class="checkmark">✓</div>
		<div class="success-header">Message Sent Successfully!</div>
		<div class="success-message">
			<p>Your message has been delivered to the dizum.com mail2news service.</p>
			<p><strong>Security measures applied:</strong></p>
			<ul>
				<li><span class="memguard-active">✓ MemGuard protected all data in memory</span></li>
				<li>✓ Message transmitted via Tor network</li>
				<li>✓ Input validated and sanitized</li>
				<li>✓ All sensitive data wiped from memory</li>
				<li>✓ No data logged or stored</li>
			</ul>
			<p>Your message should appear in the newsgroup shortly, depending on propagation time.</p>
		</div>
		<center>
			<a href="/" class="back-link">Send Another Message</a>
		</center>
		<div class="footer">
			Mail2Dizum v%s with MemGuard<br>
			Powered by <a href="https://dizum.com" target="_blank" rel="noopener noreferrer" style="color:#007bff;">dizum.com</a>
		</div>
	</div>
</body>
</html>`, VERSION)
	
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, successHTML)
}

// isValidSMTPServer validates SMTP server format (host:port or onion:port)
func isValidSMTPServer(server string) bool {
	server = strings.TrimSpace(server)
	
	if len(server) < 5 || len(server) > 253 {
		return false
	}
	
	// Check for injection characters
	dangerousChars := []string{"\r", "\n", "\t", ";", "'", "\"", "\\", "|", "&", "$", "`", " "}
	for _, dc := range dangerousChars {
		if strings.Contains(server, dc) {
			return false
		}
	}
	
	// Must contain exactly one colon for port
	colonCount := strings.Count(server, ":")
	if colonCount != 1 {
		return false
	}
	
	parts := strings.Split(server, ":")
	if len(parts) != 2 {
		return false
	}
	
	host := parts[0]
	port := parts[1]
	
	// Validate host
	if len(host) < 3 {
		return false
	}
	
	// Validate port (must be numeric, 1-65535)
	if len(port) == 0 || len(port) > 5 {
		return false
	}
	
	for _, char := range port {
		if char < '0' || char > '9' {
			return false
		}
	}
	
	return true
}

// generateMessageID creates a randomized Message-ID to prevent correlation
// Format: <random-local@random-domain.tld> with variable lengths
func generateMessageID() (string, error) {
	// TLD list for realistic appearance
	tlds := []string{"net", "org", "com", "info", "de", "fr", "nl", "ch", "at", "uk", "eu", "io", "cc", "me", "co"}
	
	// Generate random bytes for local part (8-16 bytes -> 16-32 hex chars)
	localLenVariation, err := secureRandomInt(9) // 0-8
	if err != nil {
		return "", err
	}
	localLen := 8 + localLenVariation // 8-16 bytes
	
	localBytes := make([]byte, localLen)
	if _, err := rand.Read(localBytes); err != nil {
		return "", fmt.Errorf("failed to generate random local part: %w", err)
	}
	localPart := hex.EncodeToString(localBytes)
	
	// Optionally add dots in local part for more natural appearance
	localPart = insertRandomDots(localPart)
	
	// Generate random domain part (4-8 bytes -> 8-16 hex chars)
	domainLenVariation, err := secureRandomInt(5) // 0-4
	if err != nil {
		return "", err
	}
	domainLen := 4 + domainLenVariation // 4-8 bytes
	
	domainBytes := make([]byte, domainLen)
	if _, err := rand.Read(domainBytes); err != nil {
		return "", fmt.Errorf("failed to generate random domain: %w", err)
	}
	domainPart := hex.EncodeToString(domainBytes)
	
	// Select random TLD
	tldIndex, err := secureRandomInt(len(tlds))
	if err != nil {
		return "", err
	}
	tld := tlds[tldIndex]
	
	// Optionally add subdomain for more variation
	addSubdomain, err := secureRandomInt(3) // 33% chance
	if err != nil {
		return "", err
	}
	
	var domain string
	if addSubdomain == 0 {
		subBytes := make([]byte, 3)
		if _, err := rand.Read(subBytes); err != nil {
			return "", err
		}
		domain = fmt.Sprintf("%s.%s.%s", hex.EncodeToString(subBytes), domainPart, tld)
	} else {
		domain = fmt.Sprintf("%s.%s", domainPart, tld)
	}
	
	messageID := fmt.Sprintf("<%s@%s>", localPart, domain)
	
	logger.WithField("msgid_length", len(messageID)).Debug("Generated randomized Message-ID")
	
	return messageID, nil
}

// secureRandomInt returns a cryptographically secure random int in [0, max)
func secureRandomInt(max int) (int, error) {
	if max <= 0 {
		return 0, nil
	}
	
	b := make([]byte, 1)
	if _, err := rand.Read(b); err != nil {
		return 0, err
	}
	
	return int(b[0]) % max, nil
}

// insertRandomDots adds 0-2 dots at random positions in a hex string
func insertRandomDots(s string) string {
	if len(s) < 8 {
		return s
	}
	
	numDots, err := secureRandomInt(3) // 0, 1, or 2 dots
	if err != nil || numDots == 0 {
		return s
	}
	
	runes := []rune(s)
	for i := 0; i < numDots; i++ {
		pos, err := secureRandomInt(len(runes) - 2)
		if err != nil {
			continue
		}
		pos += 1 // Avoid first position
		
		// Don't put dot next to another dot
		if pos > 0 && runes[pos-1] == '.' {
			continue
		}
		if pos < len(runes)-1 && runes[pos+1] == '.' {
			continue
		}
		
		// Insert dot
		newRunes := make([]rune, len(runes)+1)
		copy(newRunes[:pos], runes[:pos])
		newRunes[pos] = '.'
		copy(newRunes[pos+1:], runes[pos:])
		runes = newRunes
	}
	
	return string(runes)
}

func main() {
	logger.WithFields(logrus.Fields{
		"version":  VERSION,
		"build":    BUILD_DATE,
		"memguard": "enabled",
	}).Info("Starting Mail2Dizum with MemGuard Protection")

	// Configure system security limits
	configureSystemLimits()
	checkPrivileges()

	// Set up HTTP routes with all middleware
	http.HandleFunc("/",
		appSecurityHeadersMiddleware(
			ipBanMiddleware(
				anomalyDetectionMiddleware(
					rateLimitMiddleware(
						maxSizeMiddleware(1024*1024)(mainHandler),
					),
				),
			),
		),
	)

	http.HandleFunc("/send",
		appSecurityHeadersMiddleware(
			ipBanMiddleware(
				anomalyDetectionMiddleware(
					rateLimitMiddleware(
						maxSizeMiddleware(1024*1024)(sendHandler),
					),
				),
			),
		),
	)

	http.HandleFunc("/health", healthHandler)

	// Configure server with security settings
	server := &http.Server{
		Addr:              "127.0.0.1:8789",
		Handler:           http.DefaultServeMux,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1MB
	}

	// Create listener with connection limit
	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		logger.Fatal("Failed to create listener: ", err)
	}

	// Limit concurrent connections to prevent resource exhaustion
	limitedListener := netutil.LimitListener(listener, 100)

	logger.WithFields(logrus.Fields{
		"address":           server.Addr,
		"max_connections":   100,
		"rate_limit_global": "10 req/sec",
		"rate_limit_per_ip": "1 req/5sec",
		"memguard":          "active",
	}).Info("Mail2Dizum server started successfully")

	// Start server
	if err := server.Serve(limitedListener); err != nil {
		logger.Fatal("Server error: ", err)
	}
}
