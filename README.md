<p><a href:https://mail2dizum.virebent.art:4443>Mail2Dizum</a> è un'applicazione scritta in Go che consente l'invio di messaggi ai newsgroup tramite emails dirette al mail2news gateway di <a href="https://dizum.com/">dizum.com</a>. </p>
<p>La comunicazione avviene in modo anonimo attraverso la rete Tor, utilizzando un server SMTP .onion per garantire privacy e sicurezza.</p>

Per utilizzare mail2dizum, sono necessari i seguenti requisiti:

Go (Golang): Assicurati di avere Go installato. 
Puoi scaricarlo da https://go.dev/dl/.
Tor: Deve essere configurato e in esecuzione sulla tua macchina.
Apache2: Configurato come proxy per fornire un'interfaccia HTTPS sicura.

<b>Installazione</b><ul>
<li>1. Installa Go<br>
<p>Scarica e installa Go dalla pagina ufficiale: https://go.dev/dl/.</p></li>

<p>Verifica l'installazione eseguendo:</p>

<code>go version</code><br>
<p>Assicurati che il comando restituisca una versione valida di Go.</p>

<li>2. Configura Tor<br></li>
<p>Assicurati che Tor sia installato e configurato. Puoi installarlo utilizzando il gestore di pacchetti del tuo sistema operativo:</p>

Compilazione del progetto<br>
<p>Clona questo repository e naviga nella directory del progetto:</p>

<code>git clone https://github.com/gabrix73/mail2dizum.git<br>
cd mail2dizum</code>

<li><p>3. Compila il codice Go:</p></li>

<code>go build -o mail2dizum mail2dizum.go</code>
<p>Questo genererà un eseguibile chiamato mail2dizum.</p>

<p>Configurazione del proxy Apache2</p>
<p>Per fornire un'interfaccia sicura con TLS, configuriamo Apache2 come proxy per mail2dizum.</p>

<li>4. Installa Apache2<br></li>
<p>Se non è già installato, su debian puoi farlo con:</p>
<code>sudo apt install apache2<br>
a2enmod ssl proxy proxy_http proxy_http2 proxy_balancer proxy_connect headers remoteip http2 ssl</code>

<li>5. Configura un VirtualHost<br></li>
<p>Crea un nuovo file di configurazione per Apache:</p>

<code>sudo nano /etc/apache2/sites-available/mail2dizum.conf</code>
Aggiungi il seguente contenuto:<br>
<pre><code>
    <IfModule mod_ssl.c>
    <VirtualHost *:4443>
        ServerName mail2dizum.domain
        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html
        Protocols h2 http/1.1
        # SSL Engine e percorsi certificati
        SSLEngine on
        SSLCertificateFile /etc/letsencrypt/live/mail2dizum.domain/fullchain.pem
        SSLCertificateKeyFile /etc/letsencrypt/live/mail2dizum.domain/privkey.pem
        SSLCACertificateFile /etc/letsencrypt/live/mail2dizum.domain/chain.pem

        # Configurazione del proxy verso il server Go
        ProxyPreserveHost On
        ProxyPass / http://localhost:8080/
        ProxyPassReverse / http://localhost:8080/

        # Configurazione di sicurezza aggiuntiva
        SSLProxyEngine On
        SSLProxyCheckPeerCN off
        SSLProxyCheckPeerName off

        # No Access Logs
        LogFormat "\"%{X-Forwarded-For}i\" %l %u %t \"%r\" %>s %b" anonymized_log
        #LogLevel warn
        #ErrorLog ${APACHE_LOG_DIR}/mail2news_ssl_error.log
        CustomLog ${APACHE_LOG_DIR}/mail2news_ssl_access.log anonymized_log
        # CORS headers
        Header always set Access-Control-Allow-Origin "*"
        Header always set Access-Control-Allow-Methods "GET, POST, OPTIONS"
        Header always set Access-Control-Allow-Headers "Origin, X-Requested-With, Content-Type, Accept"        
        Header always set X-Frame-Options DENY
        Header always set X-Content-Type-Options nosniff
     </ VirtualHost>
</ IfModule>
</code></pre>
<li>6. Abilita la configurazione:<br></li>

<code>sudo a2ensite mail2dizum.conf
sudo systemctl restart apache2</code>

<li>7. Avvia il server mail2news:<br></li>

<code>./mail2dizum</code>
<p>Il server sarà disponibile su http://127.0.0.1:8080. Tramite il proxy Apache2 configurato, sarà accessibile via HTTPS al dominio configurato (ad esempio, https://mail2dizum.example.com).</p></ul>

<b>Librerie Go utilizzate:</b>
<p><ul><li>net/http: Per gestire l'interfaccia HTTP del server.</li>
<li>net/smtp: Per la comunicazione con il server SMTP.</li>
<li>html/template: Per la generazione dell'interfaccia HTML dinamica.</li>
<li>Libreria per Tor Onion:
golang.org/x/net/proxy: Utilizzata per configurare e utilizzare un proxy SOCKS5.</li></ul></p>
<p>Questa libreria è fondamentale per l'integrazione con la rete Tor, permettendo al server mail2dizum di comunicare in modo anonimo con il server SMTP .onion.</p>
# 🔐 Mail2Dizum Security Enhanced

**A hardened, enterprise-grade web interface for secure Usenet posting via dizum.com mail2news service**

Mail2Dizum Security Enhanced is a complete security overhaul of the original mail2news interface, implementing military-grade protection mechanisms for anonymous and secure communication through Usenet networks. This version transforms a simple web-to-email gateway into a fortress-level secure communication platform.

## 🛡️ Security Enhancements

### 🧠 **Memory Protection**
- **MemGuard Integration**: All sensitive data (emails, messages, subjects) encrypted in protected memory enclaves
- **Anti-Dump Protection**: Resistance against memory dumps, cold boot attacks, and forensic analysis
- **Automatic Cleanup**: Zero-residue memory management with guaranteed data destruction
- **Root-Level Protection**: Security maintained even against privileged system access

### 🚫 **Advanced Threat Detection**
- **Intelligent IP Banning**: Automated blocking of suspicious IPs with behavioral analysis
- **Anomaly Detection**: Real-time scanning for attack patterns, scanners, and malicious tools
- **Rate Limiting**: Sophisticated request throttling (5 requests/minute per IP)
- **User-Agent Analysis**: Detection and blocking of automated tools and reconnaissance attempts

### 🔒 **Web Application Security**
- **CSRF Protection**: Secure token-based protection against cross-site request forgery
- **Input Sanitization**: Complete HTML sanitization using Bluemonday strict policy
- **XSS Prevention**: Multi-layered protection against cross-site scripting attacks
- **Header Injection Defense**: Detection and blocking of HTTP header injection attempts

### 📊 **Security Monitoring & Observability**
- **Prometheus Metrics**: Real-time security events tracking and performance monitoring
- **Structured Logging**: Comprehensive audit trails with zero sensitive data exposure
- **Health Monitoring**: Continuous system health checks and availability verification
- **Alert Integration**: Ready for integration with alerting systems (Grafana, AlertManager)

### 🌐 **Network Security**
- **Enhanced Tor Integration**: Hardened SOCKS5 proxy with connection monitoring
- **Connection Limiting**: Maximum concurrent connections control for DoS protection
- **Timeout Management**: Configurable timeouts for all network operations
- **SSL/TLS Ready**: Optimized for deployment behind reverse proxies with SSL termination

### 🔧 **System Hardening**
- **Resource Limits**: Memory, file descriptor, and process limitations
- **Privilege Management**: Non-root execution recommendations and privilege checks
- **Static Compilation**: Zero external dependencies for maximum security
- **Core Dump Protection**: Disabled core dumps to prevent information leakage

### 📝 **Protocol Compliance & Standards**
- **RFC 5536 Compliant**: Full Usenet message format compliance
- **UTF-8 Exclusive**: International character support with consistent encoding
- **MIME Standards**: Proper MIME headers for newsreader compatibility
- **Threading Support**: Complete References header implementation for conversation threading

## ⚡ **Performance Improvements**

- **Memory Efficiency**: Optimized memory usage with automatic cleanup
- **Connection Pooling**: Enhanced Tor connection management
- **Reduced Latency**: Streamlined request processing pipeline
- **Scalable Architecture**: Ready for horizontal scaling and load balancing

## 🎯 **Deployment Features**

- **Docker Ready**: Optimized for containerized deployment
- **Apache Integration**: Seamless integration with Apache reverse proxy
- **Zero Configuration**: Works out-of-the-box with sane security defaults
- **Production Hardened**: Enterprise-ready with comprehensive security controls

## 🔍 **Monitoring & Maintenance**

- **Security Dashboard**: Real-time security events visualization
- **Performance Metrics**: Detailed performance and availability tracking
- **Audit Logging**: Complete security audit trails for compliance
- **Vulnerability Scanning**: Regular dependency vulnerability assessment

---

**🚀 Live Demo**: [https://mail2dizum.virebent.art:4443](https://mail2dizum.virebent.art:4443)

**📖 Documentation**: Complete security documentation and deployment guides included

**🔒 Security First**: Every feature designed with security as the primary concern

**⚡ Ready to Deploy**: Production-ready with enterprise-grade security controls

<b>Licenza</b>
Questo progetto è distribuito senza alcuna licenza.

Contatti
Per ulteriori informazioni o supporto, contattaci all'email: <A HREF="&#109;&#97;&#105;&#108;&#116;&#111;&#58;%69%6E%66%6F%40%76%69%72%65%62%65%6E%74%2E%61%72%74"> info (AT) virebent DOT art</a>.
