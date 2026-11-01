package policy

import (
	"encoding/base64"
)

// b64Impl returns base64(user + ":" + password); used only inside Authorize.
func (a *Auth) b64Impl() string {
	return base64.StdEncoding.EncodeToString([]byte(a.user + ":" + a.password))
}
