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

	// ErrInvalidPassword is returned when a password hash comparison fails.
	ErrInvalidPassword = errors.New("invalid password")

	// ErrHashFailed is returned when an error occurs during the hashing process.
	ErrHashFailed = errors.New("failed to hash password")
)
