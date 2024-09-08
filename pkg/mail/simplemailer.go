package mail

// SimpleMailer is basic mail sending type
// Currently does nothing
type SimpleMailer struct {
}

func (m SimpleMailer) SendWarning(from, to string, content string) {
	// TODO mail sending
}
