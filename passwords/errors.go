package passwords

import "errors"

// Sentinel errors for the passwords module.
var (
	// ErrPasswordTooShort is returned when a password does not meet the minimum length requirement.
	ErrPasswordTooShort = errors.New("password is too short")

	// ErrPasswordTooLong is returned when a password exceeds the maximum length requirement.
	ErrPasswordTooLong = errors.New("password is too long")

	// ErrPasswordMissingUppercase is returned when a password requires an uppercase character but lacks one.
	ErrPasswordMissingUppercase = errors.New("password must contain at least one uppercase letter")

	// ErrPasswordMissingLowercase is returned when a password requires a lowercase character but lacks one.
	ErrPasswordMissingLowercase = errors.New("password must contain at least one lowercase letter")

	// ErrPasswordMissingNumber is returned when a password requires a numeric character but lacks one.
	ErrPasswordMissingNumber = errors.New("password must contain at least one number")

	// ErrPasswordMissingSpecial is returned when a password requires a special character but lacks one.
	ErrPasswordMissingSpecial = errors.New("password must contain at least one special character")

	// ErrPasswordBreached is returned when a password is rejected for being known-compromised
	// or too common — either it matched the policy's denylist or a configured BreachChecker
	// reported it as breached.
	ErrPasswordBreached = errors.New("password is known to be compromised")

	// ErrInvalidPassword is returned when a password hash comparison fails.
	ErrInvalidPassword = errors.New("invalid password")

	// ErrHashFailed is returned when an error occurs during the hashing process.
	ErrHashFailed = errors.New("failed to hash password")
)
