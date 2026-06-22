// Package auth implements the SMTP AUTH PLAIN token format used by both
// the Python and Go implementations of smtp-tunnel.
//
// Token wire format (after base64 decode):
//
//      username:timestamp:hmac_b64
//
// where hmac_b64 = base64(HMAC_SHA256(secret,
//                                       "smtp-tunnel-auth:username:timestamp"))
//
// A legacy 2-field format (timestamp:hmac_b64) is also accepted on the
// server side for backwards compatibility with pre-multi-user clients.
package auth

import (
        "crypto/hmac"
        "crypto/rand"
        "crypto/sha256"
        "crypto/subtle"
        "encoding/base64"
        "fmt"
        "strconv"
        "strings"
        "time"
)

// MaxAge is the maximum allowed clock skew between client and server.
const MaxAge = 5 * time.Minute

// authPrefix is the canonical message prefix used in the HMAC.
const authPrefix = "smtp-tunnel-auth"

// GenerateToken returns a base64-encoded SMTP AUTH PLAIN token for the
// given username/secret at the given time.
func GenerateToken(secret, username string, now time.Time) string {
        ts := now.Unix()
        msg := fmt.Sprintf("%s:%s:%d", authPrefix, username, ts)
        mac := hmac.New(sha256.New, []byte(secret))
        mac.Write([]byte(msg))
        macB64 := base64.StdEncoding.EncodeToString(mac.Sum(nil))
        plain := fmt.Sprintf("%s:%d:%s", username, ts, macB64)
        return base64.StdEncoding.EncodeToString([]byte(plain))
}

// VerifyToken validates a base64-encoded token against a single secret
// (single-user / legacy mode). Returns the username (possibly empty if
// the token used the legacy format) and a boolean indicating success.
func VerifyToken(token, secret string, now time.Time) (string, bool) {
        return VerifyTokenMultiUser(token, map[string]string{"": secret}, now, true)
}

// VerifyTokenMultiUser validates a token against a map of username -> secret.
// On success it returns the matched username. The allowLegacy flag controls
// whether the 2-field legacy format (without a username) is accepted; when
// accepted, the returned username is the empty string.
func VerifyTokenMultiUser(token string, users map[string]string, now time.Time, allowLegacy bool) (string, bool) {
        decoded, err := base64.StdEncoding.DecodeString(token)
        if err != nil {
                return "", false
        }
        parts := strings.Split(string(decoded), ":")
        if len(parts) != 3 && !(allowLegacy && len(parts) == 2) {
                return "", false
        }

        var username, tsStr string
        if len(parts) == 3 {
                username, tsStr = parts[0], parts[1]
        } else {
                username, tsStr = "", parts[0]
        }

        ts, err := strconv.ParseInt(tsStr, 10, 64)
        if err != nil {
                return "", false
        }
        if diff := now.Sub(time.Unix(ts, 0)); diff > MaxAge || diff < -MaxAge {
                return "", false
        }

        secret, ok := users[username]
        if !ok {
                return "", false
        }

        // Re-derive the expected token and constant-time compare the whole
        // base64 string. Constant-time on the *outer* base64 means an
        // attacker cannot use timing to distinguish which byte of the HMAC
        // was wrong.
        expected := GenerateToken(secret, username, time.Unix(ts, 0))
        if subtle.ConstantTimeCompare([]byte(token), []byte(expected)) != 1 {
                return "", false
        }
        return username, true
}

// GenerateSecret returns a 32-byte URL-safe random secret suitable for use
// as a user's pre-shared key. It panics if the system CSPRNG fails — that
// is a fatal configuration error.
func GenerateSecret() string {
        b := make([]byte, 32)
        if _, err := rand.Read(b); err != nil {
                panic("crypto/rand failed: " + err.Error())
        }
        return base64.RawURLEncoding.EncodeToString(b)
}
