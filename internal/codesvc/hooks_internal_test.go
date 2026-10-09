package codesvc

import "github.com/JLugagne/egauth/internal/cookie"

func BreakBindCookie(s *Service) { s.cookies = cookie.Policy{} }
