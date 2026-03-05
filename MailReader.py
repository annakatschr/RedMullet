import imaplib
import email

class MailReader():
    def retrieve_emails(self):
        imap = imaplib.IMAP4_SSL("imap.gmail.com")
        imap.login("email@gmail.com", "password")

        imap.select("INBOX")
        status, messages = imap.search(None, "UNSEEN")

        for msg_id in messages[0].split():
            status, msg_data = imap.fetch(msg_id, "(RFC822)")
            msg = email.message_from_bytes(msg_data[0][1])
            print("From:", msg["From"])
            print("Subject:", msg["Subject"])

        imap.close()
        imap.logout()


