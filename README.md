Mail2Dizum è un'applicazione scritta in Go che consente l'invio di messaggi ai newsgroup tramite email. 
La comunicazione avviene in modo anonimo attraverso la rete Tor, utilizzando un server SMTP .onion per garantire privacy e sicurezza.

Per utilizzare mail2news, sono necessari i seguenti requisiti:

Go (Golang): Assicurati di avere Go installato. 
Puoi scaricarlo da https://go.dev/dl/.
Tor: Deve essere configurato e in esecuzione sulla tua macchina con il supporto SOCKS5.
Apache2: Configurato come proxy per fornire un'interfaccia HTTPS sicura.

Installazione
1. Installa Go
Scarica e installa Go dalla pagina ufficiale: https://go.dev/dl/.

Verifica l'installazione eseguendo:

go version
Assicurati che il comando restituisca una versione valida di Go.

2. Configura Tor
Assicurati che Tor sia installato e configurato. Puoi installarlo utilizzando il gestore di pacchetti del tuo sistema operativo:

Compilazione del progetto
Clona questo repository e naviga nella directory del progetto:

git clone https://github.com/tuo-username/mail2news.git
cd mail2news

Compila il codice Go:

go build -o mail2news mail2news.go
Questo genererà un eseguibile chiamato mail2news.

Configurazione del proxy Apache2
Per fornire un'interfaccia sicura con TLS, configuriamo Apache2 come proxy per mail2news.

1. Installa Apache2
Se non è già installato, su debian puoi farlo con:
sudo apt install apache2
sudo a2enmod ssl proxy proxy_http proxy_balancer proxy_connect

3. Configura un VirtualHost
Crea un nuovo file di configurazione per Apache:

sudo nano /etc/apache2/sites-available/mail2news.conf
Aggiungi il seguente contenuto:

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

Abilita la configurazione:

sudo a2ensite mail2news.conf
sudo systemctl restart apache2

Avviare il server Go
Avvia il server mail2news:

./mail2news
Il server sarà disponibile su http://127.0.0.1:8443. Tramite il proxy Apache2 configurato, sarà accessibile via HTTPS al dominio configurato (ad esempio, https://mail2news.example.com).

Librerie Go utilizzate
Standard Libraries
net/http: Per gestire l'interfaccia HTTP del server.
net/smtp: Per la comunicazione con il server SMTP.
html/template: Per la generazione dell'interfaccia HTML dinamica.
Libreria per Tor Onion
golang.org/x/net/proxy: Utilizzata per configurare e utilizzare un proxy SOCKS5. 
Questa libreria è fondamentale per l'integrazione con la rete Tor, permettendo al server mail2news di comunicare in modo anonimo con il server SMTP .onion.
Debugging
Problemi comuni
Errore SOCKS5: host unreachable

Assicurati che Tor sia in esecuzione (sudo systemctl status tor).
Prova a connetterti manualmente al server .onion usando torsocks telnet.
Apache non instrada correttamente

Controlla i log di Apache:
bash
Copier le code
sudo tail -f /var/log/apache2/mail2news_error.log
Errore durante l'invio dell'email

Assicurati che il server SMTP .onion sia raggiungibile e funzioni correttamente.
Contributi
Siamo aperti a contributi! Sentiti libero di inviare una pull request o aprire una segnalazione per migliorare il progetto.

Licenza
Questo progetto è distribuito senza alcuna licenza.

Contatti
Per ulteriori informazioni o supporto, contattaci all'email: support@virebent.art.
