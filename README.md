Mail2Dizum è un'applicazione scritta in Go che consente l'invio di messaggi ai newsgroup tramite emails dirette al mail2news gateway di dizum.com. 
La comunicazione avviene in modo anonimo attraverso la rete Tor, utilizzando un server SMTP .onion per garantire privacy e sicurezza.

Per utilizzare mail2news, sono necessari i seguenti requisiti:

Go (Golang): Assicurati di avere Go installato. 
Puoi scaricarlo da https://go.dev/dl/.
Tor: Deve essere configurato e in esecuzione sulla tua macchina con il supporto SOCKS5.
Apache2: Configurato come proxy per fornire un'interfaccia HTTPS sicura.

Installazione
1. Installa Go<br>
<p>Scarica e installa Go dalla pagina ufficiale: https://go.dev/dl/.</p>

<p>Verifica l'installazione eseguendo:</p>

go version<br>
<p>Assicurati che il comando restituisca una versione valida di Go.</p>

2. Configura Tor<br>
<p>Assicurati che Tor sia installato e configurato. Puoi installarlo utilizzando il gestore di pacchetti del tuo sistema operativo:</p>

Compilazione del progetto<br>
<p>Clona questo repository e naviga nella directory del progetto:</p>

<code>git clone https://github.com/tuo-username/mail2news.git<br>
cd mail2news</code>

<p>Compila il codice Go:</p>

<code>go build -o mail2news mail2news.go</code>
<p>Questo genererà un eseguibile chiamato mail2news.</p>

<p>Configurazione del proxy Apache2</p>
<p>Per fornire un'interfaccia sicura con TLS, configuriamo Apache2 come proxy per mail2news.</p>

1. Installa Apache2<br>
<p>Se non è già installato, su debian puoi farlo con:</p>
<code></code>sudo apt install apache2
sudo a2enmod ssl proxy proxy_http proxy_balancer proxy_connect</code>

3. Configura un VirtualHost<br>
<p>Crea un nuovo file di configurazione per Apache:</p>

<code>sudo nano /etc/apache2/sites-available/mail2news.conf</code>
Aggiungi il seguente contenuto:<br>
<code>
<VirtualHost *:443>
    ServerName mail2news.example.com

    SSLEngine on
    SSLCertificateFile /etc/letsencrypt/live/mail2news.example.com/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/mail2news.example.com/privkey.pem

    ProxyPreserveHost On
    ProxyPass / http://127.0.0.1:8443/
    ProxyPassReverse / http://127.0.0.1:8443/

    ErrorLog ${APACHE_LOG_DIR}/mail2news_error.log
    CustomLog ${APACHE_LOG_DIR}/mail2news_access.log combined
</VirtualHost>
</code>
Abilita la configurazione:<br>

<code>sudo a2ensite mail2news.conf
sudo systemctl restart apache2</code>

Avviare il server Go<br>
Avvia il server mail2news:<br>

<code>./mail2news</code>
<p>Il server sarà disponibile su http://127.0.0.1:8443. Tramite il proxy Apache2 configurato, sarà accessibile via HTTPS al dominio configurato (ad esempio, https://mail2news.example.com).</p>

Librerie Go utilizzate
Standard Libraries
net/http: Per gestire l'interfaccia HTTP del server.
net/smtp: Per la comunicazione con il server SMTP.
html/template: Per la generazione dell'interfaccia HTML dinamica.
Libreria per Tor Onion
golang.org/x/net/proxy: Utilizzata per configurare e utilizzare un proxy SOCKS5. 
Questa libreria è fondamentale per l'integrazione con la rete Tor, permettendo al server mail2news di comunicare in modo anonimo con il server SMTP .onion.

Licenza
Questo progetto è distribuito senza alcuna licenza.

Contatti
Per ulteriori informazioni o supporto, contattaci all'email: support@virebent.art.
