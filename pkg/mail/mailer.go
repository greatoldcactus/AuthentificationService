package mail

// Mailer is Interface for sending mail
type Mailer interface {
	SendWarning(from, to string, content string)
}
