/*
 * Mail2Dizum with MemGuard v1.5.0
 * Secure web interface for Usenet posting via dizum.com mail2news service
 * v1.5.0 - Added file logging and full SMTP debug
 */

package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/awnumar/memguard"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/netutil"
	"golang.org/x/net/proxy"
	"golang.org/x/time/rate"
)

const (
	VERSION                  = "1.5.4-memguard"
	BUILD_DATE               = "2026-08-28"
	LOG_FILE                 = "/home/ocourier/mail2dizum/mail2dizum.log"
	RESTRICTED_SMTP_RELAY    = "qee4i7sags6phsvb2yodwecfj7noimfhhalsjktsvikrwotxzis3raad.onion:25"
	MAIL2NEWS_INGRESS_DOMAIN = "xilb7y4kj6u6qfo45o3yk2kilfv54ffukzei3puonuqlncy7cn2afwyd.onion"
)

var (
	globalLimiter = rate.NewLimiter(rate.Every(time.Second), 10)
	ipLimiters    = make(map[string]*rate.Limiter)
	ipLimiterMu   sync.Mutex
	logger        = logrus.New()
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
	logDir := filepath.Dir(LOG_FILE)
	os.MkdirAll(logDir, 0750)

	logFile, err := os.OpenFile(LOG_FILE, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
	if err != nil {
		logger.SetOutput(os.Stdout)
	} else {
		logger.SetOutput(io.MultiWriter(os.Stdout, logFile))
	}

	logger.SetFormatter(&logrus.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: "2006-01-02 15:04:05",
		DisableColors:   true,
	})
	logger.SetLevel(logrus.DebugLevel)
	memguard.CatchInterrupt()
	go securityCacheCleanup()
	go ipLimiterCleanup()

	logger.WithFields(logrus.Fields{
		"version": VERSION, "log_file": LOG_FILE,
	}).Info("Mail2Dizum initialized")
}

func ipLimiterCleanup() {
	ticker := time.NewTicker(30 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		ipLimiterMu.Lock()
		ipLimiters = make(map[string]*rate.Limiter)
		ipLimiterMu.Unlock()
	}
}

func getIPLimiter(ip string) *rate.Limiter {
	ipLimiterMu.Lock()
	defer ipLimiterMu.Unlock()
	if len(ipLimiters) > 1000 {
		ipLimiters = make(map[string]*rate.Limiter)
	}
	limiter, exists := ipLimiters[ip]
	if !exists {
		limiter = rate.NewLimiter(rate.Every(5*time.Second), 2)
		ipLimiters[ip] = limiter
	}
	return limiter
}

func hashIP(ip string) string {
	h := sha256.Sum256([]byte(ip))
	return hex.EncodeToString(h[:])[:16]
}

func NewSecureMessage(from, newsgroup, subject, message, references string) (*SecureMessage, error) {
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
	return sm, nil
}

func (sm *SecureMessage) Destroy() {
	sm.from, sm.newsgroup, sm.subject, sm.message, sm.references = nil, nil, nil, nil, nil
}

func (sm *SecureMessage) GetFrom() (string, error) {
	if sm.from == nil {
		return "", nil
	}
	locked, err := sm.from.Open()
	if err != nil {
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
		return "", err
	}
	defer locked.Destroy()
	return string(locked.Bytes()), nil
}

func securityCacheCleanup() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for range ticker.C {
		securityCache.mutex.Lock()
		now := time.Now()
		for ip, banTime := range securityCache.bannedIPs {
			if now.Sub(banTime) > 24*time.Hour {
				delete(securityCache.bannedIPs, ip)
			}
		}
		securityCache.failedAttempts = make(map[string]int)
		securityCache.mutex.Unlock()
	}
}

func isIPBanned(ip string) bool {
	securityCache.mutex.RLock()
	defer securityCache.mutex.RUnlock()
	banTime, exists := securityCache.bannedIPs[ip]
	return exists && time.Since(banTime) < 24*time.Hour
}

func banIP(ip, reason string) {
	securityCache.mutex.Lock()
	defer securityCache.mutex.Unlock()
	securityCache.bannedIPs[ip] = time.Now()
	logger.WithFields(logrus.Fields{"ip_hash": hashIP(ip), "reason": reason}).Warn("IP banned")
}

func recordFailedAttempt(ip string) {
	securityCache.mutex.Lock()
	defer securityCache.mutex.Unlock()
	securityCache.failedAttempts[ip]++
	if securityCache.failedAttempts[ip] >= 10 {
		securityCache.bannedIPs[ip] = time.Now()
		delete(securityCache.failedAttempts, ip)
	}
}

func getClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}

	// Trust forwarding headers ONLY when the direct TCP peer is the local
	// reverse proxy (loopback). Otherwise a remote client could forge
	// X-Forwarded-For / X-Real-IP to bypass rate limiting and IP bans.
	peer := net.ParseIP(host)
	if peer != nil && peer.IsLoopback() {
		if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
			// Use the last hop appended by our own proxy, not the
			// left-most client-controlled entry.
			parts := strings.Split(fwd, ",")
			candidate := strings.TrimSpace(parts[len(parts)-1])
			if net.ParseIP(candidate) != nil {
				return candidate
			}
		}
		if real := strings.TrimSpace(r.Header.Get("X-Real-IP")); real != "" {
			if net.ParseIP(real) != nil {
				return real
			}
		}
	}
	return host
}

func ipBanMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if isIPBanned(getClientIP(r)) {
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
			http.Error(w, "Server busy", http.StatusServiceUnavailable)
			return
		}
		if !getIPLimiter(clientIP).Allow() {
			recordFailedAttempt(clientIP)
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	}
}

func securityHeadersMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, private")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'")
		next.ServeHTTP(w, r)
	}
}

func anomalyDetectionMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clientIP := getClientIP(r)
		ua := strings.ToLower(r.UserAgent())
		badPatterns := []string{"sqlmap", "nmap", "nikto", "burp", "metasploit", "scanner", "exploit", "dirbuster", "gobuster", "wfuzz"}
		for _, p := range badPatterns {
			if strings.Contains(ua, p) {
				banIP(clientIP, "bad UA: "+p)
				http.Error(w, "Access denied", http.StatusForbidden)
				return
			}
		}
		for _, vals := range r.Header {
			for _, v := range vals {
				if strings.ContainsAny(v, "\r\n") {
					banIP(clientIP, "header injection")
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

func validateFromField(from string) error {
	from = strings.TrimSpace(from)
	if len(from) < 5 {
		return fmt.Errorf("too short")
	}

	open := strings.LastIndex(from, "<")
	close := strings.LastIndex(from, ">")
	if open == -1 || close == -1 || close <= open {
		return fmt.Errorf("format: Name <email@domain>")
	}
	if strings.TrimSpace(from[close+1:]) != "" {
		return fmt.Errorf("nothing after email")
	}

	username := strings.TrimSpace(from[:open])
	email := strings.TrimSpace(from[open+1 : close])

	if username == "" {
		return fmt.Errorf("name required")
	}

	words := strings.Fields(username)
	if len(words) == 0 || len(words) > 2 {
		return fmt.Errorf("1-2 words for name")
	}

	for _, w := range words {
		if len(w) > 12 {
			return fmt.Errorf("word max 12 chars")
		}
		for _, c := range w {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
				return fmt.Errorf("alphanumeric only")
			}
		}
	}

	dangerous := []string{"\r", "\n", "\t", ";", "'", "\"", "\\", "|", "&", "$", "`"}
	for _, d := range dangerous {
		if strings.Contains(email, d) {
			return fmt.Errorf("invalid chars in email")
		}
	}

	at := strings.Index(email, "@")
	if at <= 0 || at == len(email)-1 || strings.Count(email, "@") != 1 {
		return fmt.Errorf("invalid email")
	}

	domain := email[at+1:]
	if len(domain) < 3 || !strings.Contains(domain, ".") {
		return fmt.Errorf("invalid domain")
	}
	return nil
}

func sanitizeAndValidateInput(r *http.Request) (*SecureMessage, error) {
	from := strings.TrimSpace(r.FormValue("from"))
	newsgroup := strings.TrimSpace(r.FormValue("newsgroup"))
	subject := strings.TrimSpace(r.FormValue("subject"))
	message := strings.TrimSpace(r.FormValue("message"))
	references := strings.TrimSpace(r.FormValue("reply_to"))

	if from == "" || newsgroup == "" || subject == "" || message == "" {
		return nil, fmt.Errorf("all required fields must be filled")
	}
	if err := validateFromField(from); err != nil {
		return nil, fmt.Errorf("from: %s", err)
	}
	if !isValidNewsgroup(newsgroup) {
		return nil, fmt.Errorf("invalid newsgroup")
	}
	if len(subject) > 200 {
		return nil, fmt.Errorf("subject too long")
	}
	if len(message) > 50000 {
		return nil, fmt.Errorf("message too long")
	}

	if references != "" {
		// Only block injection chars - $ is allowed (common in Usenet Message-IDs)
		dangerous := []string{"\r", "\n", "\t", ";", "'", "\"", "\\", "|", "&", "`"}
		for _, d := range dangerous {
			if strings.Contains(references, d) {
				return nil, fmt.Errorf("invalid chars in references")
			}
		}
		if len(references) > 500 {
			return nil, fmt.Errorf("references too long")
		}
	}
	return NewSecureMessage(from, newsgroup, subject, message, references)
}

func isValidNewsgroup(ng string) bool {
	ng = strings.TrimSpace(ng)
	if len(ng) < 3 || len(ng) > 500 {
		return false
	}

	dangerous := []string{"\r", "\n", "\t", ";", "'", "\"", "\\", "|", "&", "$", "`"}
	for _, d := range dangerous {
		if strings.Contains(ng, d) {
			return false
		}
	}

	groups := strings.Split(ng, ",")
	if len(groups) > 3 {
		return false
	}

	for _, g := range groups {
		g = strings.TrimSpace(g)
		if len(g) < 3 || len(g) > 200 || !strings.Contains(g, ".") {
			return false
		}
		if strings.HasPrefix(g, ".") || strings.HasSuffix(g, ".") || strings.Contains(g, "..") {
			return false
		}
		for _, c := range g {
			ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '+' || c == '_'
			if !ok {
				return false
			}
		}
	}
	return true
}

// generateMessageID builds an RFC 5536 compliant Message-ID under the
// dizum.com domain. We set it explicitly so that neither the intermediate
// onion SMTP relay nor dizum overwrites it (MTAs preserve an existing
// Message-ID). The local part is timestamp + cryptographically random hex
// for anti-correlation.
func generateMessageID() (string, error) {
	randBytes := make([]byte, 12)
	if _, err := rand.Read(randBytes); err != nil {
		return "", err
	}
	ts := time.Now().UTC().Format("20060102150405")
	return fmt.Sprintf("<%s.%s@dizum.com>", ts, hex.EncodeToString(randBytes)), nil
}

// smtpCommand sends a command and logs the full response
func smtpCommand(conn net.Conn, reader *bufio.Reader, cmd string) (int, string, error) {
	cmdType := strings.Split(cmd, " ")[0]
	logger.WithField("cmd", cmdType).Debug("SMTP >>> sending")

	_, err := fmt.Fprintf(conn, "%s\r\n", cmd)
	if err != nil {
		return 0, "", fmt.Errorf("send error: %w", err)
	}

	response, err := reader.ReadString('\n')
	if err != nil {
		return 0, "", fmt.Errorf("read error: %w", err)
	}

	response = strings.TrimSpace(response)
	logger.WithField("response", response).Debug("SMTP <<< received")

	if len(response) < 3 {
		return 0, response, fmt.Errorf("invalid response")
	}

	var code int
	fmt.Sscanf(response[:3], "%d", &code)
	return code, response, nil
}

func buildEnvelopeRecipient(smtpServer, newsgroup string, antispam bool, now time.Time) (string, error) {
	if smtpServer != RESTRICTED_SMTP_RELAY {
		if antispam {
			return "mail2news_nospam@dizum.com", nil
		}
		return "mail2news@dizum.com", nil
	}

	if antispam {
		return "", fmt.Errorf("antispam recipient is not supported by the restricted SMTP relay")
	}

	groups := strings.Split(newsgroup, ",")
	for i, group := range groups {
		groups[i] = strings.ToLower(strings.TrimSpace(group))
	}

	return fmt.Sprintf(
		"mail2news-%s-%s@%s",
		now.UTC().Format("20060102"),
		strings.Join(groups, "="),
		MAIL2NEWS_INGRESS_DOMAIN,
	), nil
}

// sendMailThroughTor with full SMTP debug logging
func sendMailThroughTor(smtpServer string, secureMsg *SecureMessage, antispam bool) error {
	defer secureMsg.Destroy()

	logger.WithField("server", smtpServer).Info("=== Starting SMTP session ===")
	start := time.Now()

	fromHeader, _ := secureMsg.GetFrom()
	newsgroup, _ := secureMsg.GetNewsgroup()
	subject, _ := secureMsg.GetSubject()
	message, _ := secureMsg.GetMessage()
	references, _ := secureMsg.GetReferences()

	envelopeFrom := "mail2news@dizum.com"
	recipient, err := buildEnvelopeRecipient(smtpServer, newsgroup, antispam, time.Now())
	if err != nil {
		return err
	}

	logger.WithFields(logrus.Fields{
		"envelope_from": envelopeFrom,
		"recipient":     recipient,
		"newsgroup":     newsgroup,
		"antispam":      antispam,
	}).Debug("Message parameters")

	messageID, err := generateMessageID()
	if err != nil {
		logger.WithError(err).Error("Failed to generate Message-ID")
		return err
	}
	logger.WithField("message_id", messageID).Debug("Generated Message-ID")

	// RFC 2822 Date format - required by dizum
	dateHeader := time.Now().UTC().Format("Mon, 02 Jan 2006 15:04:05 -0700")
	logger.WithField("date_header", dateHeader).Debug("Generated Date header")

	var msgBuilder strings.Builder
	msgBuilder.WriteString(fmt.Sprintf("From: %s\r\n", fromHeader))
	msgBuilder.WriteString(fmt.Sprintf("Date: %s\r\n", dateHeader))
	msgBuilder.WriteString(fmt.Sprintf("Newsgroups: %s\r\n", newsgroup))
	msgBuilder.WriteString(fmt.Sprintf("Subject: %s\r\n", subject))
	// Explicit Message-ID under dizum.com so no relay along the path reassigns it.
	msgBuilder.WriteString(fmt.Sprintf("Message-ID: %s\r\n", messageID))
	msgBuilder.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	msgBuilder.WriteString("MIME-Version: 1.0\r\n")
	if references != "" {
		msgBuilder.WriteString(fmt.Sprintf("References: %s\r\n", references))
	}
	msgBuilder.WriteString("\r\n")
	msgBuilder.WriteString(message)

	fullMessage := msgBuilder.String()
	logger.WithField("msg_size", len(fullMessage)).Debug("Message built")

	logger.Debug("Connecting via Tor SOCKS5...")
	dialer, err := proxy.SOCKS5("tcp", "127.0.0.1:9050", nil, proxy.Direct)
	if err != nil {
		logger.WithError(err).Error("SOCKS5 proxy error")
		return fmt.Errorf("SOCKS5 error: %w", err)
	}

	conn, err := dialer.Dial("tcp", smtpServer)
	if err != nil {
		logger.WithError(err).Error("Tor connection failed")
		return fmt.Errorf("Tor connection error: %w", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(60 * time.Second))
	logger.Debug("Tor connection established")

	reader := bufio.NewReader(conn)

	greeting, err := reader.ReadString('\n')
	if err != nil {
		logger.WithError(err).Error("Failed to read greeting")
		return fmt.Errorf("greeting read error: %w", err)
	}
	logger.WithField("greeting", strings.TrimSpace(greeting)).Info("SMTP server greeting")

	code, resp, err := smtpCommand(conn, reader, "HELO localhost")
	if err != nil {
		logger.WithError(err).Error("HELO failed")
		return err
	}
	if code != 250 {
		logger.WithFields(logrus.Fields{"code": code, "response": resp}).Error("HELO rejected")
		return fmt.Errorf("HELO rejected: %s", resp)
	}

	code, resp, err = smtpCommand(conn, reader, fmt.Sprintf("MAIL FROM:<%s>", envelopeFrom))
	if err != nil {
		logger.WithError(err).Error("MAIL FROM failed")
		return err
	}
	if code != 250 {
		logger.WithFields(logrus.Fields{"code": code, "response": resp}).Error("MAIL FROM rejected")
		return fmt.Errorf("MAIL FROM rejected: %s", resp)
	}

	code, resp, err = smtpCommand(conn, reader, fmt.Sprintf("RCPT TO:<%s>", recipient))
	if err != nil {
		logger.WithError(err).Error("RCPT TO failed")
		return err
	}
	if code != 250 {
		logger.WithFields(logrus.Fields{"code": code, "response": resp}).Error("RCPT TO rejected")
		return fmt.Errorf("RCPT TO rejected: %s", resp)
	}

	code, resp, err = smtpCommand(conn, reader, "DATA")
	if err != nil {
		logger.WithError(err).Error("DATA failed")
		return err
	}
	if code != 354 {
		logger.WithFields(logrus.Fields{"code": code, "response": resp}).Error("DATA rejected")
		return fmt.Errorf("DATA rejected: %s", resp)
	}

	logger.Debug("Sending message body...")
	_, err = fmt.Fprintf(conn, "%s\r\n.\r\n", fullMessage)
	if err != nil {
		logger.WithError(err).Error("Failed to send message body")
		return fmt.Errorf("body send error: %w", err)
	}

	finalResp, err := reader.ReadString('\n')
	if err != nil {
		logger.WithError(err).Error("Failed to read final response")
		return fmt.Errorf("final response error: %w", err)
	}
	finalResp = strings.TrimSpace(finalResp)
	logger.WithField("final_response", finalResp).Info("SMTP final response after DATA")

	var finalCode int
	fmt.Sscanf(finalResp[:3], "%d", &finalCode)

	if finalCode != 250 {
		logger.WithFields(logrus.Fields{"code": finalCode, "response": finalResp}).Error("Message NOT accepted!")
		return fmt.Errorf("message rejected: %s", finalResp)
	}

	fmt.Fprintf(conn, "QUIT\r\n")
	quitResp, _ := reader.ReadString('\n')
	logger.WithField("quit_response", strings.TrimSpace(quitResp)).Debug("QUIT response")

	duration := time.Since(start)
	logger.WithFields(logrus.Fields{
		"duration_ms": duration.Milliseconds(),
		"newsgroup":   newsgroup,
		"message_id":  messageID,
		"final_code":  finalCode,
	}).Info("=== SMTP session completed successfully ===")

	return nil
}

func configureSystemLimits() {
	var rLimit syscall.Rlimit
	rLimit.Max, rLimit.Cur = 1024, 1024
	syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rLimit)
	rLimit.Max, rLimit.Cur = 0, 0
	syscall.Setrlimit(syscall.RLIMIT_CORE, &rLimit)
}

func checkPrivileges() {
	if os.Geteuid() == 0 {
		logger.Warn("Running as root - not recommended")
	} else {
		logger.Info("Running as non-privileged user")
	}
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<meta http-equiv="Cache-Control" content="no-store, no-cache, must-revalidate, private">
	<title>Mail2Dizum v{{.Version}}</title>
	<style>
		body { background-color: white; color: black; font-family: Arial, sans-serif; margin: 0; padding: 0; }
		.container { width: 90%; max-width: 600px; margin: 20px auto; padding: 20px; border: 2px solid red; background-color: black; color: white; }
		input[type="text"], textarea, select { width: 100%; padding: 8px; margin-top: 5px; box-sizing: border-box; background-color: #222; color: white; border: 1px solid #444; }
		button { background-color: red; color: white; padding: 10px 20px; border: none; cursor: pointer; font-size: 16px; margin-top: 10px; }
		button:hover { background-color: darkred; }
		footer { margin-top: 20px; text-align: center; background-color: red; color: black; padding: 10px; }
		footer a { color: black; text-decoration: none; }
		.security-notice { background-color: #1a1a1a; border: 1px solid #444; padding: 10px; margin: 10px 0; color: #aaa; font-size: 12px; border-radius: 4px; }
		.version-info { background-color: #0d47a1; color: white; padding: 10px; margin: 10px 0; border-radius: 4px; font-size: 12px; text-align: center; }
		.memguard-active { color: #4ade80; font-weight: bold; }
		.warning { background-color: #ff6b6b; color: white; padding: 5px; margin: 10px 0; border-radius: 3px; font-size: 11px; }
		.field-hint { color: #888; font-size: 11px; margin-top: 3px; margin-bottom: 10px; }
		label { margin-top: 10px; display: block; }
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
			• Message-ID under dizum.com (randomized, anti-correlation)
		</div>
		<p>Post to Usenet newsgroups anonymously through the Dizum mail2news gateway.</p>
		<form method="POST" action="/send">
			<label for="from">From:</label>
			<input type="text" id="from" name="from" placeholder="Name Surname <email@example.com>" required autocomplete="off">
			<div class="field-hint">Format: 1-2 words (max 12 chars each) + email in &lt;brackets&gt;</div>

			<label for="newsgroup">Newsgroup:</label>
			<input type="text" id="newsgroup" name="newsgroup" placeholder="alt.test" required autocomplete="off">
			<div class="field-hint">Max 3 newsgroups separated by comma</div>

			<label for="subject">Subject:</label>
			<input type="text" id="subject" name="subject" maxlength="200" required autocomplete="off">

			<label for="message">Message:</label>
			<textarea id="message" name="message" rows="10" maxlength="50000" required></textarea>

			<label for="reply_to">References (Message-ID for replies):</label>
			<input type="text" id="reply_to" name="reply_to" placeholder="<msgid@domain.tld> (optional)" autocomplete="off">
			<div class="field-hint">Leave empty for new posts, use Message-ID for replies</div>

			<label for="smtp_choice">SMTP Server:</label>
			<select id="smtp_choice" name="smtp_choice">
				<option value="4uwpi53u524xdphjw2dv5kywsxmyjxtk4facb76jgl3sc3nda3sz4fqd.onion:25" selected>Dizum Onion SMTP</option>
				<option value="custom">Custom SMTP Server</option>
			</select>
			<div id="custom_smtp_div" style="display:none; margin-top:10px;">
				<label for="smtp_custom">Custom SMTP Server:</label>
				<input type="text" id="smtp_custom" name="smtp_custom" placeholder="smtp.example.com:25" autocomplete="off">
			</div>
			<button type="submit">Send via Tor</button>
		</form>
		<div class="warning">⚠️ Rate limited: Max 2 messages per 5 seconds per user</div>
	</div>
	<footer>
		<a href="https://github.com/gabrix73/mail2dizum" target="_blank" rel="noopener noreferrer">GitHub</a> |
		<a href="https://dizum.com" target="_blank" rel="noopener noreferrer">Dizum.com</a> |
		<a href="https://yamn.virebent.art" target="_blank" rel="noopener noreferrer">Victor Hostile</a>
		<div style="font-size: 10px; margin-top: 5px; color: #666;">Mail2Dizum v{{.Version}}</div>
	</footer>
	<script>
		document.getElementById("smtp_choice").addEventListener("change", function() {
			document.getElementById("custom_smtp_div").style.display = this.value === "custom" ? "block" : "none";
		});
		window.addEventListener('beforeunload', function() {
			document.getElementById('from').value = '';
			document.getElementById('message').value = '';
			document.getElementById('subject').value = '';
			document.getElementById('reply_to').value = '';
			document.getElementById('smtp_custom').value = '';
		});
		if (window.history.replaceState) { window.history.replaceState(null, null, window.location.href); }
	</script>
</body>
</html>`

func healthHandler(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	requestCount++
	count := requestCount
	mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status":"healthy","version":"%s","requests":%d}`, VERSION, count)
}

func mainHandler(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	requestCount++
	mu.Unlock()
	tmpl, err := template.New("page").Parse(htmlTemplate)
	if err != nil {
		logger.WithError(err).Error("Template parse error")
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	data := struct{ Version, BuildDate string }{VERSION, BUILD_DATE}
	tmpl.Execute(w, data)
}

func sendHandler(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	requestCount++
	mu.Unlock()

	logger.Info("=== New send request ===")

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		logger.WithError(err).Error("Form parse error")
		http.Error(w, "Error reading form", http.StatusBadRequest)
		return
	}

	secureMsg, err := sanitizeAndValidateInput(r)
	if err != nil {
		logger.WithError(err).Warn("Validation failed")
		http.Error(w, fmt.Sprintf("Validation error: %s", err), http.StatusBadRequest)
		return
	}

	antispam := r.FormValue("antispam") == "on"
	smtpChoice := r.FormValue("smtp_choice")

	var smtpServer string
	if smtpChoice == "custom" {
		smtpServer = strings.TrimSpace(r.FormValue("smtp_custom"))
		if smtpServer == "" || !isValidSMTPServer(smtpServer) {
			secureMsg.Destroy()
			http.Error(w, "Invalid SMTP server", http.StatusBadRequest)
			return
		}
	} else {
		smtpServer = smtpChoice
	}

	if smtpServer == "" {
		secureMsg.Destroy()
		http.Error(w, "No SMTP server", http.StatusBadRequest)
		return
	}

	if err := sendMailThroughTor(smtpServer, secureMsg, antispam); err != nil {
		logger.WithError(err).Error("Send failed")
		http.Error(w, "Failed to send message. Check logs.", http.StatusInternalServerError)
		return
	}

	logger.Info("Message sent successfully")

	successHTML := fmt.Sprintf(`<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Message Sent</title>
<style>body{font-family:Arial;background:#f0f0f0;padding:20px}.container{max-width:600px;margin:0 auto;background:white;padding:30px;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,0.1)}.success{color:#28a745;font-size:24px;text-align:center}.checkmark{color:#28a745;font-size:48px;text-align:center}.back{display:inline-block;background:#007bff;color:white;padding:10px 20px;text-decoration:none;border-radius:4px;margin-top:20px}.memguard{color:#4ade80;font-weight:bold}</style></head>
<body><div class="container"><div class="checkmark">✓</div><div class="success">Message Sent Successfully!</div>
<p>Your message has been delivered to dizum.com mail2news service.</p>
<ul><li><span class="memguard">✓ MemGuard protected</span></li><li>✓ Transmitted via Tor</li><li>✓ Message-ID under dizum.com</li></ul>
<p>Message should appear in newsgroup shortly.</p>
<center><a href="/" class="back">Send Another Message</a></center>
<div style="margin-top:30px;text-align:center;color:#666;font-size:12px">Mail2Dizum v%s</div>
</div></body></html>`, VERSION)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, successHTML)
}

func isValidSMTPServer(server string) bool {
	server = strings.TrimSpace(server)
	if len(server) < 5 || len(server) > 253 {
		return false
	}

	dangerous := []string{"\r", "\n", "\t", ";", "'", "\"", "\\", "|", "&", "$", "`", " "}
	for _, d := range dangerous {
		if strings.Contains(server, d) {
			return false
		}
	}

	if strings.Count(server, ":") != 1 {
		return false
	}

	parts := strings.Split(server, ":")
	if len(parts) != 2 || len(parts[0]) < 3 || len(parts[1]) == 0 || len(parts[1]) > 5 {
		return false
	}

	for _, c := range parts[1] {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func main() {
	logger.WithFields(logrus.Fields{"version": VERSION, "log_file": LOG_FILE}).Info("Starting Mail2Dizum")

	configureSystemLimits()
	checkPrivileges()

	http.HandleFunc("/", securityHeadersMiddleware(ipBanMiddleware(anomalyDetectionMiddleware(rateLimitMiddleware(maxSizeMiddleware(1024*1024)(mainHandler))))))
	http.HandleFunc("/send", securityHeadersMiddleware(ipBanMiddleware(anomalyDetectionMiddleware(rateLimitMiddleware(maxSizeMiddleware(1024*1024)(sendHandler))))))
	http.HandleFunc("/health", healthHandler)

	server := &http.Server{
		Addr:              "127.0.0.1:8789",
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		logger.Fatal("Listener error: ", err)
	}

	limitedListener := netutil.LimitListener(listener, 100)

	logger.WithFields(logrus.Fields{"address": server.Addr, "max_conn": 100}).Info("Server started")

	if err := server.Serve(limitedListener); err != nil {
		logger.Fatal("Server error: ", err)
	}
}
