<p><strong>Mail2Dizum</strong> è un'applicazione scritta in Go che consente l'invio di messaggi ai newsgroup tramite emails dirette al mail2news gateway di <a href="https://dizum.com/">dizum.com</a>. <br>
La comunicazione avviene in modo anonimo attraverso la rete Tor, utilizzando un server SMTP .onion per garantire privacy e sicurezza.</p>

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

<b>Licenza</b>
Questo progetto è distribuito senza alcuna licenza.

Contatti
Per ulteriori informazioni o supporto, contattaci all'email: <A HREF="&#109;&#97;&#105;&#108;&#116;&#111;&#58;%69%6E%66%6F%40%76%69%72%65%62%65%6E%74%2E%61%72%74"> info (AT) virebent DOT art</a>.
