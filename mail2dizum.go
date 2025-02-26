package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/smtp"
	"regexp"
	"strings"

	"golang.org/x/net/proxy"
)

const htmlTemplate = `
<!DOCTYPE html>
<html lang="en">
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
		<h2>Send Emails to Mail2News Dizum dot COM</h2>
		<p>The Mail2News protocol allows you to send emails as usenet postings.</p>
		<p>We do this through the Tor/Onion network.<br>
		</p>
		<form method="POST" action="/send">
			<label for="from">From:</label><br>
			<input type="text" id="from" name="from" placeholder="User Name<email@address>" required><br><br>

			<label for="newsgroup">Newsgroup:</label><br>
			<input type="text" id="newsgroup" name="newsgroup" required><br><br>

			<label for="subject">Subject:</label><br>
			<input type="text" id="subject" name="subject" required><br><br>

			<label for="message">Message:</label><br>
			<textarea id="message" name="message" rows="10" cols="50" required></textarea><br><br>

			<label for="reply_to">References:</label><br>
			<input type="text" id="reply_to" name="reply_to"><br><br>

			<label for="antispam">AntiSpam On:</label>
			<input type="checkbox" id="antispam" name="antispam"><br><br>

			<label for="smtp_choice">SMTP Server:</label><br>
			<select id="smtp_choice" name="smtp_choice">
				<option value="pncuiafaqnsi2mnj3ij7uqyxdu2ofzjwwzvhxid5cdxkvjhil2pszbid.onion:25">pncuiafaqnsi2mnj3ij7uqyxdu2ofzjwwzvhxid5cdxkvjhil2pszbid.onion:25</option>
				<option value="dkudsc3rn7r4m2gdvje6vmcnmglmt2m6whc3oazd65oyi7mvfbgfnzqd.onion:25">dkudsc3rn7r4m2gdvje6vmcnmglmt2m6whc3oazd65oyi7mvfbgfnzqd.onion:25</option>
				<option value="xilb7y4kj6u6qfo45o3yk2kilfv54ffukzei3puonuqlncy7cn2afwyd.onion:25">xilb7y4kj6u6qfo45o3yk2kilfv54ffukzei3puonuqlncy7cn2afwyd.onion:25</option>
                <option value="4uwpi53u524xdphjw2dv5kywsxmyjxtk4facb76jgl3sc3nda3sz4fqd.onion:25" selected>4uwpi53u524xdphjw2dv5kywsxmyjxtk4facb76jgl3sc3nda3sz4fqd.onion:25</option>
				<option value="custom">Other (custom)</option>
			</select>
			<br><br>
			<div id="custom_smtp_div" style="display:none;">
				<label for="smtp_custom">Custom SMTP:</label><br>
				<input type="text" id="smtp_custom" name="smtp_custom" placeholder="smtp.example.com:25"><br>
				<small>Additional possible addresses at SEC3: <a href="https://www.sec3.net/misc/mail-relays.html" target="_blank">this link</a>.</small>
				<br><br>
			</div>

			<button type="submit">Send</button>
		</form>
	</div>
	<footer>
<div style="text-align: center;">
  <div>
    <a href="https://github.com/gabrix73/mail2dizum.git" target="_blank">
      <svg role="img" viewBox="0 0 24 24" width="24" height="24" xmlns="http://www.w3.org/2000/svg">
        <title>GitHub</title>
        <path fill="currentColor" d="M12 0C5.373 0 0 5.373 0 12c0 5.303 3.438 9.8 8.205 11.387.6.111.82-.261.82-.58 0-.285-.011-1.04-.017-2.04-3.338.724-4.042-1.612-4.042-1.612-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.73.083-.73 1.205.085 1.838 1.237 1.838 1.237 1.07 1.834 2.807 1.304 3.492.997.108-.775.419-1.305.762-1.605-2.665-.3-5.466-1.333-5.466-5.93 0-1.312.47-2.383 1.236-3.222-.124-.303-.536-1.523.117-3.176 0 0 1.008-.322 3.301 1.23a11.51 11.51 0 013.003-.404 11.48 11.48 0 013.003.404c2.291-1.552 3.297-1.23 3.297-1.23.655 1.653.243 2.873.12 3.176.77.84 1.235 1.91 1.235 3.222 0 4.61-2.805 5.625-5.475 5.922.43.37.823 1.103.823 2.222 0 1.606-.015 2.898-.015 3.293 0 .321.216.697.825.579C20.565 21.796 24 17.303 24 12c0-6.627-5.373-12-12-12z"/>
      </svg>
      GitHub
    </a>
  </div>
  <div>
    <a href="https://yamn.virebent.art" target="_blank">
      Victor Hostile Communicazion Center
    </a>
  </div>
  <div>
    <a href="https://dizum.com" target="_blank">
      Powered by dizum.com
    </a>
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
	</script>
</body>
</html>
`

// sendMailThroughTor sends the email via Tor using the specified SMTP server.
// The envelope sender is fixed (mail2news@dizum.com); the recipient varies based on the antispam option.
func sendMailThroughTor(smtpServer, fromHeader, newsgroup, subject, message, references string, antispam bool) error {
	envelopeFrom := "mail2news@dizum.com"
	var recipient string
	if antispam {
		recipient = "mail2news_nospam@dizum.com"
	} else {
		recipient = "mail2news@dizum.com"
	}

	// Compose the email message
	msg := strings.Join([]string{
		fmt.Sprintf("From: %s", fromHeader),
		fmt.Sprintf("To: %s", recipient),
		fmt.Sprintf("Newsgroups: %s", newsgroup),
		fmt.Sprintf("Subject: %s", subject),
		"X-No-Archive: Yes",
		"Content-Type: text/plain; charset=utf-8",
		"Content-Transfer-Encoding: 8bit",
		"MIME-Version: 1.0",
		fmt.Sprintf("References: %s", references),
		"",
		message,
	}, "\r\n")

	// Configure the SOCKS5 proxy for Tor
	log.Println("Configuring SOCKS5 proxy...")
	dialer, err := proxy.SOCKS5("tcp4", "127.0.0.1:9050", nil, proxy.Direct)
	if err != nil {
		log.Printf("SOCKS5 configuration error: %v", err)
		return fmt.Errorf("SOCKS5 configuration error: %v", err)
	}

	// Connect to the SMTP server via the proxy
	log.Printf("Attempting to connect to SMTP server %s via SOCKS5...", smtpServer)
	conn, err := dialer.Dial("tcp4", smtpServer)
	if err != nil {
		log.Printf("SOCKS5 connection error to %s: %v", smtpServer, err)
		return fmt.Errorf("SOCKS5 connection error to %s: %v", smtpServer, err)
	}
	log.Println("SOCKS5 connection established successfully.")
	defer conn.Close()

	// Create the SMTP client
	host := strings.Split(smtpServer, ":")[0]
	log.Println("Creating SMTP connection without TLS...")
	client, err := smtp.NewClient(conn, host)
	if err != nil {
		log.Printf("SMTP client creation error: %v", err)
		return fmt.Errorf("SMTP client creation error: %v", err)
	}
	log.Println("SMTP client created successfully.")
	defer client.Close()

	// Send MAIL FROM command (using fixed envelopeFrom)
	log.Println("Sending MAIL FROM command...")
	if err := client.Mail(envelopeFrom); err != nil {
		log.Printf("MAIL FROM command error: %v", err)
		return fmt.Errorf("MAIL FROM command error: %v", err)
	}

	// Send RCPT TO command (based on antispam option)
	log.Println("Sending RCPT TO command...")
	if err := client.Rcpt(recipient); err != nil {
		log.Printf("RCPT TO command error: %v", err)
		return fmt.Errorf("RCPT TO command error: %v", err)
	}

	// Write the message body
	log.Println("Writing message body...")
	wc, err := client.Data()
	if err != nil {
		log.Printf("DATA command error: %v", err)
		return fmt.Errorf("DATA command error: %v", err)
	}
	_, err = wc.Write([]byte(msg))
	if err != nil {
		log.Printf("Message body writing error: %v", err)
		return fmt.Errorf("Message body writing error: %v", err)
	}
	wc.Close()

	// Close the SMTP connection
	log.Println("Closing SMTP connection...")
	if err := client.Quit(); err != nil {
		log.Printf("QUIT command error: %v", err)
		return fmt.Errorf("QUIT command error: %v", err)
	}

	log.Println("Message sent successfully.")
	return nil
}

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		tmpl, err := template.New("webpage").Parse(htmlTemplate)
		if err != nil {
			log.Printf("Error parsing HTML template: %s\n", err.Error())
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		if err := tmpl.Execute(w, nil); err != nil {
			log.Printf("Error executing HTML template: %s\n", err.Error())
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
	})

	http.HandleFunc("/send", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Error reading form", http.StatusBadRequest)
			return
		}

		// Read form fields
		fromHeader := r.FormValue("from")
		newsgroup := r.FormValue("newsgroup")
		subject := r.FormValue("subject")
		message := r.FormValue("message")
		references := r.FormValue("reply_to")
		antispam := r.FormValue("antispam") == "on"

		// Select the SMTP server
		smtpChoice := r.FormValue("smtp_choice")
		var smtpServer string
		if smtpChoice == "custom" {
			smtpServer = r.FormValue("smtp_custom")
		} else {
			smtpServer = smtpChoice
		}
		if smtpServer == "" {
			http.Error(w, "Invalid SMTP address", http.StatusBadRequest)
			return
		}

		// Validate the From field (format: User Name<email@address>)
		fromPattern := regexp.MustCompile("^[^<>]+<[^<>@]+@[^<>]+>$")
		if !fromPattern.MatchString(fromHeader) {
			http.Error(w, "Invalid From. Required format: User Name<email@address>", http.StatusBadRequest)
			return
		}
		newsgroupPattern := regexp.MustCompile(`^(?:[a-zA-Z0-9._-]+)(?:\s*,\s*[a-zA-Z0-9._-]+){0,2}$`)
		if !newsgroupPattern.MatchString(newsgroup) {
			http.Error(w, "Invalid newsgroup - It must contain up to three groups separated by commas", http.StatusBadRequest)
			return
		}
		if !regexp.MustCompile(`^[^\r\n]+$`).MatchString(subject) {
			http.Error(w, "Invalid subject", http.StatusBadRequest)
			return
		}

		// Validate the message (at least one character allowed, any character)
		if !regexp.MustCompile("(?s)^.+$").MatchString(message) {
			http.Error(w, "Invalid message", http.StatusBadRequest)
			return
		}

		// Send the message via Tor
		if err := sendMailThroughTor(smtpServer, fromHeader, newsgroup, subject, message, references, antispam); err != nil {
			log.Printf("Error sending message: %s\n", err)
			http.Error(w, fmt.Sprintf("Error sending message: %s", err), http.StatusInternalServerError)
			return
		}

		log.Println("Message sent successfully.")
		fmt.Fprintf(w, "<html><body><h3>Message sent successfully!</h3><a href=\"/\">Go back</a></body></html>")
	})

	log.Println("Server listening on http://localhost:8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}
