package tokens

import (
	"testing"
	"time"
)

func TestNewRefreshToken(t *testing.T) {
	var _ RefreshToken = NewRefreshToken("hello", time.Now())
}
