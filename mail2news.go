package main

import (
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/smtp"
	"strings"

	"golang.org/x/net/proxy"
)

// Template HTML per l'interfaccia web
const htmlTemplate = `
<!DOCTYPE html>
<html lang="it">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Victor Mail2News Interface</title>
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
	</style>
</head>
<body>
	<div class="container">
		<h2>Invia Messaggio al Newsgroup</h2>
		<p>Il protocollo Mail2News permette di inviare messaggi ai newsgroup via email.<br>
		Nel nostro caso, utilizziamo un server SMTP su dominio <strong>onion</strong> per garantire l'anonimato e la privacy dei messaggi.<br>
		Tutti i post inviati tramite questa interfaccia sono protetti dalla rete Tor, assicurando che la privacy dell'utente sia mantenuta durante l'invio.</p>
	        <p><code>ExcludeExitNodes: GB,US,AU,CA,NZ,CH,TR,UA,RU,SA,KP,AE,IL,JP,DK,FR,NL,NO,BE,SE,ES,IT</code></p><br>
        	<form method="POST" action="/send">
			<label for="newsgroup">Newsgroup:</label><br>
			<input type="text" id="newsgroup" name="newsgroup" required><br><br>
			<label for="subject">Oggetto:</label><br>
			<input type="text" id="subject" name="subject" required><br><br>
			<label for="message">Messaggio:</label><br>
			<textarea id="message" name="message" rows="10" cols="50" required></textarea><br><br>
			<label for="reply_to">References:</label><br>
			<input type="text" id="reply_to" name="reply_to"><br><br>
			<button type="submit">Invia</button>
		</form>
	</div>
	<footer>
		Powered by <a href="https://dizum.com" target="_blank">dizum.com</a>
	</footer>
</body>
</html>
`

// Funzione per inviare l'email attraverso Tor usando il server SMTP
func sendMailThroughTor(newsgroup, subject, message, references string) error {
	// Configurazione SMTP
	smtpServer := "4uwpi53u524xdphjw2dv5kywsxmyjxtk4facb76jgl3sc3nda3sz4fqd.onion:25"
	from := "noreply@yamn.virebent.art"
	to := "mail2news_nospam@dizum.com"

	// Corpo del messaggio con intestazioni standard
	msg := strings.Join([]string{
		fmt.Sprintf("From: %s", from),
		fmt.Sprintf("To: %s", to),
		fmt.Sprintf("Newsgroups: %s", newsgroup),
		fmt.Sprintf("Subject: %s", subject),
		"X-No-Archive: Yes", // Header personalizzato per evitare l'archiviazione
		"Content-Type: text/plain; charset=utf-8", // Impostazione del charset UTF-8
		"Content-Transfer-Encoding: 8bit", // Encoding del messaggio
		"MIME-Version: 1.0", // Versione MIME
		fmt.Sprintf("References: %s", references),
		"",
		message,
	}, "\r\n")

	// Configura il proxy SOCKS5 per Tor
	log.Println("Configurazione del proxy SOCKS5...")
	dialer, err := proxy.SOCKS5("tcp4", "127.0.0.1:9050", nil, proxy.Direct)
	if err != nil {
		log.Printf("Errore configurazione SOCKS5: %v", err)
		return fmt.Errorf("Errore configurazione SOCKS5: %v", err)
	}

	// Usa il dialer SOCKS5 per creare una connessione
	log.Printf("Tentativo di connessione al server SMTP %s tramite SOCKS5...", smtpServer)
	conn, err := dialer.Dial("tcp4", smtpServer)
	if err != nil {
		log.Printf("Errore connessione SOCKS5 a %s: %v", smtpServer, err)
		return fmt.Errorf("Errore connessione SOCKS5 a %s: %v", smtpServer, err)
	}
	log.Println("Connessione SOCKS5 stabilita con successo.")
	defer conn.Close()

	// Wrappa la connessione in TLS (opzionale se richiesto dal server SMTP)
	log.Println("Creazione della connessione SMTP senza TLS...")
	client, err := smtp.NewClient(conn, strings.Split(smtpServer, ":")[0])
	if err != nil {
		log.Printf("Errore creazione client SMTP: %v", err)
		return fmt.Errorf("Errore creazione client SMTP: %v", err)
	}
	log.Println("Client SMTP creato con successo.")
	defer client.Close()

	// Invia il comando MAIL FROM
	log.Println("Invio comando MAIL FROM...")
	if err := client.Mail(from); err != nil {
		log.Printf("Errore comando MAIL FROM: %v", err)
		return fmt.Errorf("Errore comando MAIL FROM: %v", err)
	}

	// Invia il comando RCPT TO
	log.Println("Invio comando RCPT TO...")
	if err := client.Rcpt(to); err != nil {
		log.Printf("Errore comando RCPT TO: %v", err)
		return fmt.Errorf("Errore comando RCPT TO: %v", err)
	}

	// Scrive il corpo del messaggio
	log.Println("Scrittura del corpo del messaggio...")
	wc, err := client.Data()
	if err != nil {
		log.Printf("Errore comando DATA: %v", err)
		return fmt.Errorf("Errore comando DATA: %v", err)
	}
	_, err = wc.Write([]byte(msg))
	if err != nil {
		log.Printf("Errore scrittura corpo messaggio: %v", err)
		return fmt.Errorf("Errore scrittura corpo messaggio: %v", err)
	}
	wc.Close()

	// Chiude la connessione SMTP
	log.Println("Chiusura della connessione SMTP...")
	if err := client.Quit(); err != nil {
		log.Printf("Errore comando QUIT: %v", err)
		return fmt.Errorf("Errore comando QUIT: %v", err)
	}

	log.Println("Messaggio inviato con successo.")
	return nil
}

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		tmpl, err := template.New("webpage").Parse(htmlTemplate)
		if err != nil {
			log.Printf("Errore durante il parsing del template HTML: %s\n", err.Error())
			http.Error(w, "Errore interno del server", http.StatusInternalServerError)
			return
		}
		err = tmpl.Execute(w, nil)
		if err != nil {
			log.Printf("Errore durante l'esecuzione del template HTML: %s\n", err.Error())
			http.Error(w, "Errore interno del server", http.StatusInternalServerError)
		}
	})

	http.HandleFunc("/send", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			r.ParseForm()
			newsgroup := r.FormValue("newsgroup")
			subject := r.FormValue("subject")
			message := r.FormValue("message")
			references := r.FormValue("reply_to")

			err := sendMailThroughTor(newsgroup, subject, message, references)
			if err != nil {
				log.Printf("Errore durante l'invio del messaggio: %s\n", err)
				http.Error(w, fmt.Sprintf("Errore durante l'invio del messaggio: %s", err), http.StatusInternalServerError)
				return
			}

			log.Println("Messaggio inviato con successo.")
			fmt.Fprintf(w, "<html><body><h3>Messaggio inviato con successo!</h3><a href=\"/\">Torna indietro</a></body></html>")
		} else {
			http.Error(w, "Metodo non supportato", http.StatusMethodNotAllowed)
		}
	})

	// Creazione di un listener IPv4
	listener, err := net.Listen("tcp4", ":8443")
	if err != nil {
		log.Fatalf("Errore durante la creazione del listener IPv4: %s\n", err)
	}

	log.Println("Server in ascolto su http://localhost:8443")
	if err := http.Serve(listener, nil); err != nil {
		log.Fatalf("Errore durante l'esecuzione del server HTTP: %s\n", err)
	}
}
