// Package breakglass is the emergency-access door's own machinery: the
// self-signed certificate its TLS listener terminates, the bcrypt credential it
// checks, and the rate limiting, lockout and timing floor that bound what an
// unauthenticated caller on the LAN can ask this root daemon to do.
//
// It is deliberately free of net/http and of internal/config: everything here
// is pure logic over an injected clock, so the riskiest new judgement in M4 —
// a credential on a LAN port — is fully testable on a Windows dev box with no
// NAS (M4 contract §15). internal/web owns the HTTP door built on top of it and
// cmd owns the CLI that writes the credential.
package breakglass

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"

	"golang.org/x/crypto/bcrypt"
)

// Password bounds (M4 contract §14).
//
// MinPasswordBytes is a length floor and nothing else: no composition rules,
// per NIST. MaxPasswordBytes bounds what a LOGIN BODY may carry — an over-long
// candidate is simply a failed attempt, answered like any other. BcryptLimit is
// where bcrypt itself stops looking, and CheckPassword (the CLI's rule) refuses
// past it rather than letting the tail be silently ignored.
const (
	MinPasswordBytes = 12
	MaxPasswordBytes = 1024
	BcryptLimit      = 72
)

// Cost bounds, mirrored from config so this package needs no import of it.
const (
	DefaultCost = 11
	MinCost     = 10
	MaxCost     = 15
)

// ErrNoPassword is returned when no hash is configured at all. The HTTP door
// must answer it with the SAME body and the SAME minimum latency as a wrong
// password (contract §5.2): "no password is configured" and "wrong password"
// must not be distinguishable from outside.
var ErrNoPassword = errors.New("breakglass: no password is configured")

// ErrBadPassword is a failed verification.
var ErrBadPassword = errors.New("breakglass: password not accepted")

// CheckCost validates a bcrypt cost, resolving 0 to DefaultCost.
func CheckCost(cost int) (int, error) {
	if cost == 0 {
		return DefaultCost, nil
	}
	if cost < MinCost || cost > MaxCost {
		return 0, fmt.Errorf("breakglass: cost %d is outside %d-%d", cost, MinCost, MaxCost)
	}
	return cost, nil
}

// CheckPassword applies the rules a break-glass password must satisfy: at least
// MinPasswordBytes bytes, not only whitespace, and within what bcrypt can
// actually read. Everything else is the operator's business — no composition
// rules, per NIST.
//
// The contract (§14) says a password past BcryptLimit should be accepted with a
// notice that the tail is ignored. golang.org/x/crypto no longer truncates: as
// of v0.x it returns ErrPasswordTooLong instead, so accepting one and reporting
// a notice would produce a hashing failure a step later. Refusing it here, by
// name, is the same intent — never let an operator believe in entropy that will
// never be read — expressed the only way the library now allows. The returned
// notice survives for the passwords that ARE near the limit.
func CheckPassword(password string) (notice string, err error) {
	if len(password) < MinPasswordBytes {
		return "", fmt.Errorf("breakglass: the password must be at least %d bytes (it is %d)", MinPasswordBytes, len(password))
	}
	if strings.TrimFunc(password, unicode.IsSpace) == "" {
		return "", errors.New("breakglass: the password is only whitespace")
	}
	if len(password) > BcryptLimit {
		return "", fmt.Errorf("breakglass: the password must be at most %d bytes (it is %d): bcrypt cannot read past %d, so the rest would be silently ignored", BcryptLimit, len(password), BcryptLimit)
	}
	if len(password) > BcryptLimit-8 {
		notice = fmt.Sprintf("note: bcrypt reads at most %d bytes, and this password is %d", BcryptLimit, len(password))
	}
	return notice, nil
}

// Hash produces the bcrypt hash the config file stores. cost 0 means DefaultCost.
func Hash(password string, cost int) (string, error) {
	resolved, err := CheckCost(cost)
	if err != nil {
		return "", err
	}
	if _, err := CheckPassword(password); err != nil {
		return "", err
	}
	h, err := bcrypt.GenerateFromPassword([]byte(password), resolved)
	if err != nil {
		return "", fmt.Errorf("breakglass: hashing the password: %w", err)
	}
	return string(h), nil
}

// Verify compares a candidate against the stored hash. An empty hash is
// ErrNoPassword; a mismatch or a malformed hash is ErrBadPassword. The caller
// never distinguishes the two to a client.
func Verify(hash, password string) error {
	if strings.TrimSpace(hash) == "" {
		return ErrNoPassword
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		return ErrBadPassword
	}
	return nil
}

// HashCost reports the cost a stored hash was generated with, so `break-glass
// status` can report what is actually in force rather than what the config
// claims.
func HashCost(hash string) (int, error) {
	c, err := bcrypt.Cost([]byte(hash))
	if err != nil {
		return 0, fmt.Errorf("breakglass: reading the hash cost: %w", err)
	}
	return c, nil
}

// MeasureCost times one bcrypt at the given cost on THIS machine.
//
// The door's request deadline has to be longer than the queue can legitimately
// take, or a correct password that waited behind other verifications is
// answered as if it were wrong. How long that is cannot be a constant: bcrypt
// at cost 15 on the ARM core of a two-bay NAS is a different number from cost
// 11 on an x86 unit, by more than an order of magnitude. So it is measured
// once, on the hardware that will actually serve the door, rather than guessed
// (round-2 P2-7).
//
// It costs one hash at start-up, and only when the break-glass listener is
// armed at all.
func MeasureCost(cost int) time.Duration {
	resolved, err := CheckCost(cost)
	if err != nil {
		resolved = DefaultCost
	}
	start := time.Now()
	if _, err := bcrypt.GenerateFromPassword([]byte("measurement"), resolved); err != nil {
		return 0
	}
	// Generating and comparing do the same key-schedule work, so one stands for
	// the other closely enough for a timeout.
	return time.Since(start)
}
