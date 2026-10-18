package configcheck

import (
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

const (
	tenantLabel       = "{tenant}"
	tenantPlaceholder = "egauth-tenant-placeholder"
)

var (
	tokenRE        = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)
	segmentRE      = regexp.MustCompile(`^[A-Za-z0-9._~-]+$`)
	dnsLabelRE     = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	decimalLabelRE = regexp.MustCompile(`^[0-9]+$`)
	hexLabelRE     = regexp.MustCompile(`^0[xX][0-9a-fA-F]*$`)
)

func originProblem(s string) string {
	if !printableASCII(s) || strings.ContainsAny(s, `\%@#?`) {
		return "is not an exact origin (forbidden character)"
	}
	if !strings.HasPrefix(s, "https://") && !strings.HasPrefix(s, "http://") {
		return "is not an http(s) origin with a lower-case scheme"
	}
	tenants := strings.Count(s, tenantLabel)
	if tenants > 1 {
		return "has more than one " + tenantLabel + " label"
	}
	probe := strings.Replace(s, tenantLabel, tenantPlaceholder, 1)
	if strings.ContainsAny(probe, "{}") {
		return "has a placeholder other than " + tenantLabel
	}
	u, err := url.Parse(probe)
	if err != nil {
		return "does not parse as a URL"
	}
	if u.User != nil || u.Opaque != "" || u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return "is not an exact origin (path, query, fragment or user information)"
	}
	host := u.Hostname()
	if problem := hostProblem(host, tenants == 1); problem != "" {
		return problem
	}
	if problem := portProblem(u); problem != "" {
		return problem
	}
	if u.Scheme == "http" && !isLoopbackHost(host) {
		return "uses http on a host that is not loopback"
	}
	return ""
}

func hostProblem(host string, tenant bool) string {
	if host == "" {
		return "has no host"
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		if tenant {
			return "puts " + tenantLabel + " in an IP address"
		}
		if addr.Zone() != "" {
			return "has a zoned address"
		}
		if addr.Is4In6() {
			return "has an IPv4-mapped address; use the IPv4 form"
		}
		if addr.String() != host {
			return "has an address not in the canonical form browsers send"
		}
		return ""
	}
	labels := strings.Split(host, ".")
	if numericLabel(labels[len(labels)-1]) {
		return "ends in a numeric label that browsers parse as an IPv4 address"
	}
	placeholders := 0
	for _, l := range labels {
		if l == tenantPlaceholder {
			placeholders++
			continue
		}
		if !dnsLabelRE.MatchString(l) {
			return "has an invalid or upper-case host label " + quote(l)
		}
	}
	if !tenant {
		return ""
	}
	if placeholders != 1 || labels[0] != tenantPlaceholder {
		return "must use " + tenantLabel + " as the whole leftmost host label"
	}
	if parent := labels[1:]; len(parent) < 2 && (len(parent) != 1 || parent[0] != "localhost") {
		return "must put " + tenantLabel + " under a parent domain of at least two labels"
	}
	return ""
}

func portProblem(u *url.URL) string {
	p := u.Port()
	if p == "" {
		if strings.HasSuffix(u.Host, ":") {
			return "has an empty port"
		}
		return ""
	}
	n, err := strconv.Atoi(p)
	if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != p {
		return "has an invalid port"
	}
	if (u.Scheme == "https" && n == 443) || (u.Scheme == "http" && n == 80) {
		return "spells out the default port, which browsers never send"
	}
	return ""
}

func isLoopbackHost(host string) bool {
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.IsLoopback()
}

func pathProblem(s string) string {
	if !strings.HasPrefix(s, "/") {
		return "must start with /"
	}
	if strings.HasSuffix(s, "/") {
		return "must not end with /"
	}
	for seg := range strings.SplitSeq(s[1:], "/") {
		switch {
		case seg == "":
			return "has an empty segment"
		case seg == "." || seg == "..":
			return "has a dot segment"
		case !segmentRE.MatchString(seg):
			return "has a character outside [A-Za-z0-9._~-]"
		}
	}
	return ""
}

func tokenProblem(s string) string {
	if !tokenRE.MatchString(s) {
		return "is not a token (1 to 32 of [a-z0-9_-], starting with a letter or digit)"
	}
	return ""
}

func numericLabel(l string) bool {
	return decimalLabelRE.MatchString(l) || hexLabelRE.MatchString(l)
}

func printableASCII(s string) bool {
	for i := range len(s) {
		if s[i] <= 0x20 || s[i] >= 0x7f {
			return false
		}
	}
	return true
}
