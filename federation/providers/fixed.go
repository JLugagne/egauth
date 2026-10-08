package providers

import (
	"github.com/JLugagne/egauth/federation"
)

// Google builds the spec of Google sign-in. Google's email_verified claim is trusted for every
// domain; a false claim is still refused.
func Google(c Client) (federation.Provider, error) {
	return build(federation.Provider{
		Name:              "google",
		AuthURL:           "https://accounts.google.com/o/oauth2/v2/auth",
		TokenURL:          "https://oauth2.googleapis.com/token",
		UserInfoURL:       "https://openidconnect.googleapis.com/v1/userinfo",
		Scopes:            oidcScopes(),
		Issuer:            "https://accounts.google.com",
		JWKSURL:           "https://www.googleapis.com/oauth2/v3/certs",
		EmailVerification: federation.Always,
	}, c)
}

// Apple builds the spec of Sign in with Apple. Apple has no userinfo endpoint: the id_token
// validated against the pinned issuer and JWKS carries the identity and its email_verified claim.
// c.Secret is the short-lived signed JWT Apple requires.
func Apple(c Client) (federation.Provider, error) {
	return build(federation.Provider{
		Name:              "apple",
		AuthURL:           "https://appleid.apple.com/auth/authorize",
		TokenURL:          "https://appleid.apple.com/auth/token",
		Scopes:            []string{"openid", "email"},
		Issuer:            "https://appleid.apple.com",
		JWKSURL:           "https://appleid.apple.com/auth/keys",
		EmailVerification: federation.Always,
	}, c)
}

// GitHub builds the spec of GitHub sign-in. GitHub is plain OAuth2 with no issuer or JWKS, and the
// email of its /user endpoint carries no verification flag: the claim passed to Verified must be
// the verified flag of the primary entry of /user/emails, otherwise the email is never trusted.
func GitHub(c Client) (federation.Provider, error) {
	return build(federation.Provider{
		Name:              "github",
		AuthURL:           "https://github.com/login/oauth/authorize",
		TokenURL:          "https://github.com/login/oauth/access_token",
		UserInfoURL:       "https://api.github.com/user",
		Scopes:            []string{"read:user", "user:email"},
		EmailVerification: federation.Always,
	}, c)
}

// Facebook builds the spec of Facebook sign-in. Facebook exposes no email-verified signal, so its
// email is never trusted.
func Facebook(c Client) (federation.Provider, error) {
	return build(federation.Provider{
		Name:              "facebook",
		AuthURL:           "https://www.facebook.com/v22.0/dialog/oauth",
		TokenURL:          "https://graph.facebook.com/v22.0/oauth/access_token",
		UserInfoURL:       "https://graph.facebook.com/v22.0/me?fields=id,name,email",
		Scopes:            []string{"public_profile", "email"},
		EmailVerification: federation.Never,
	}, c)
}

// Discord builds the spec of Discord sign-in. Discord lets users hold unverified emails, so its
// email is never trusted.
func Discord(c Client) (federation.Provider, error) {
	return build(federation.Provider{
		Name:              "discord",
		AuthURL:           "https://discord.com/api/oauth2/authorize",
		TokenURL:          "https://discord.com/api/oauth2/token",
		UserInfoURL:       "https://discord.com/api/users/@me",
		Scopes:            []string{"identify", "email"},
		EmailVerification: federation.Never,
	}, c)
}

// LinkedIn builds the spec of Sign In with LinkedIn using OpenID Connect. Its email_verified claim
// is trusted for every domain; a false claim is still refused.
func LinkedIn(c Client) (federation.Provider, error) {
	return build(federation.Provider{
		Name:              "linkedin",
		AuthURL:           "https://www.linkedin.com/oauth/v2/authorization",
		TokenURL:          "https://www.linkedin.com/oauth/v2/accessToken",
		UserInfoURL:       "https://api.linkedin.com/v2/userinfo",
		Scopes:            oidcScopes(),
		Issuer:            "https://www.linkedin.com/oauth",
		JWKSURL:           "https://www.linkedin.com/oauth/openid/jwks",
		EmailVerification: federation.Always,
	}, c)
}
