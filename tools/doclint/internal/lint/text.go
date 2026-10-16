package lint

import (
	"cmp"
	"html"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

var burdenPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?is)must\s+(also|additionally)`),
	regexp.MustCompile(`(?is)remember\s+to`),
	regexp.MustCompile(`(?is)(don['’ʼ‘´]?t|do\s+not)\s+forget`),
	regexp.MustCompile(`(?is)pair\s+it\s+with`),
	regexp.MustCompile(`(?is)must\s+(match|be\s+identical|equal)`),
	regexp.MustCompile(`(?is)make\s+sure\s+(to|that|you)`),
	regexp.MustCompile(`(?is)(on|to)\s+every\s+(route|handler|call)`),
	regexp.MustCompile(`(?is)you\s+(must|should|need\s+to|have\s+to)\s+(wire|register|pass|set|configure|call|mount)`),
	regexp.MustCompile(`(?is)mount\s+(it|the\s+handler)\s+at`),
	regexp.MustCompile(`(?is)in\s+both`),
	regexp.MustCompile(`(?is)the\s+same\s.*?\s(as|you\s+passed)`),
}

const (
	escMark   = '\x00'
	openMark  = '\x01'
	closeMark = '\x02'
	tagMark   = '\x03'
)

const (
	keepComments = iota
	dropComments
	spaceComments
)

var (
	enforcedByRe  = regexp.MustCompile(`doclint:enforced-by\s+([A-Za-z_]\w*)\.([A-Za-z_]\w*)(?:\.([A-Za-z_]\w*))?`)
	backtickRe    = regexp.MustCompile("`([^`]+)`")
	codeTagRe     = regexp.MustCompile(`(?i)<code\b[^>]*>([^<\n]+)</code>`)
	docLinkRe     = regexp.MustCompile(`\[(\*?[a-z][a-z0-9_]*\.[A-Z]\w*(?:\.\w+)*)\]`)
	symbolRe      = regexp.MustCompile(`(?:^-?|\.\.\.|<-|[^\w./:@#$<-]-?)([a-z][a-z0-9_]*)\.([A-Z]\w*(?:(?:\(\))?\)?(?:\{[^{}]*\})?\.\w+)*)`)
	glueSymbolRe  = regexp.MustCompile(`\w[-/:<]([a-z][a-z0-9_]*)\.([A-Z]\w*(?:(?:\(\))?\)?(?:\{[^{}]*\})?\.\w+)*)`)
	braceRe       = regexp.MustCompile(`\{[^{}]*\}`)
	selectorRe    = regexp.MustCompile(`^(\w+)(\(\))?(\))?`)
	bannedLinkRe  = regexp.MustCompile(`(?i)(?:^|[^\w-])(SECURITY-FINDINGS\.md|AUDIT-[^\s)\]>"'` + "`" + `]*\.md|GLOBAL_REVIEW\.md|\.tasks)(?:[^\w-]|$)`)
	bannedClaim   = regexp.MustCompile(`(?i)signatures\s+verified\s+against\s+source`)
	spaceRe       = regexp.MustCompile(`\s+`)
	blockStartRe  = regexp.MustCompile(`^\s*(?:[-*+]\s|\d+[.)]\s|#)`)
	htmlTagRe     = regexp.MustCompile(`</?[A-Za-z][A-Za-z0-9-]*(?:\s(?:[^<>"'\x00-\x02]|"[^"\x00-\x02]*"|'[^'\x00-\x02]*')*)?/?>`)
	htmlCommentRe = regexp.MustCompile(`<!--(?:>|->|(?s:.*?)-->)`)
	linkDestRe    = regexp.MustCompile(`\]\([^)]*\)`)
	linkRefRe     = regexp.MustCompile(`\]\[[^\]]*\]`)
	footnoteRe    = regexp.MustCompile(`\[\^[^\]]*\]`)
	angleDestRe   = regexp.MustCompile(`\]\(<[^>]*>`)
	mdEscapeRe    = regexp.MustCompile("\\\\([!-/:-@\\[-`{-~])")
	markupChars   = strings.NewReplacer("*", "", "_", "", "~", "", "`", "", "[", "", "]", "")
	escapeOnly    = strings.NewReplacer("<!--", "", "-->", "")
	percentRe     = regexp.MustCompile(`%[0-9A-Fa-f]{2}`)
)

var confusables = map[rune]rune{
	'а': 'a', 'в': 'b', 'е': 'e', 'ё': 'e', 'к': 'k', 'м': 'm', 'н': 'h', 'о': 'o', 'р': 'p', 'с': 'c',
	'т': 't', 'у': 'y', 'х': 'x', 'і': 'i', 'ї': 'i', 'ј': 'j', 'ѕ': 's', 'ԁ': 'd', 'ԛ': 'q', 'ԝ': 'w',
	'һ': 'h', 'ӏ': 'l', 'ɡ': 'g', 'ı': 'i',
	'А': 'A', 'В': 'B', 'Е': 'E', 'Ё': 'E', 'К': 'K', 'М': 'M', 'Н': 'H', 'О': 'O', 'Р': 'P', 'С': 'C',
	'Т': 'T', 'У': 'Y', 'Х': 'X', 'І': 'I', 'Ј': 'J', 'Ѕ': 'S', 'Ԁ': 'D', 'Ԛ': 'Q', 'Ԝ': 'W', 'Һ': 'H',
	'α': 'a', 'ε': 'e', 'ι': 'i', 'κ': 'k', 'ν': 'v', 'ο': 'o', 'ρ': 'p', 'τ': 't', 'υ': 'u', 'χ': 'x',
	'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Ζ': 'Z', 'Η': 'H', 'Ι': 'I', 'Κ': 'K', 'Μ': 'M', 'Ν': 'N', 'Ο': 'O',
	'Ρ': 'P', 'Τ': 'T', 'Υ': 'Y', 'Χ': 'X',
	'ᴀ': 'a', 'ʙ': 'b', 'ᴄ': 'c', 'ᴅ': 'd', 'ᴇ': 'e', 'ꜰ': 'f', 'ɢ': 'g', 'ʜ': 'h', 'ɪ': 'i', 'ᴊ': 'j',
	'ᴋ': 'k', 'ʟ': 'l', 'ᴍ': 'm', 'ɴ': 'n', 'ᴏ': 'o', 'ᴘ': 'p', 'ʀ': 'r', 'ꜱ': 's', 'ᴛ': 't', 'ᴜ': 'u',
	'ᴠ': 'v', 'ᴡ': 'w', 'ʏ': 'y', 'ᴢ': 'z',
	'ℂ': 'C', 'ℊ': 'g', 'ℋ': 'H', 'ℌ': 'H', 'ℍ': 'H', 'ℎ': 'h', 'ℐ': 'I', 'ℑ': 'I', 'ℒ': 'L', 'ℓ': 'l',
	'ℕ': 'N', 'ℙ': 'P', 'ℚ': 'Q', 'ℛ': 'R', 'ℜ': 'R', 'ℝ': 'R', 'ℤ': 'Z', 'ℨ': 'Z', 'ℬ': 'B', 'ℭ': 'C',
	'ℯ': 'e', 'ℰ': 'E', 'ℱ': 'F', 'ℳ': 'M', 'ℴ': 'o', '𝚤': 'i', '𝚥': 'j',
}

type view struct {
	text   string
	starts []int
	marks  []int
	breaks []int
}

// ScanText applies G26 to lines, where lines[0] is at line number first of file. Burden sentences
// and the banned claim are matched per paragraph (a run of non-blank lines, also broken before a
// list item or heading) on every rendered reading of the text: Markdown emphasis, link
// destinations, hard breaks and entities are dropped, look-alike and compatibility letters and
// Unicode spaces fold to ASCII, and HTML comments and tags (which may wrap) are each read kept,
// removed and replaced by a space, so neither wrapping nor markup hides a sentence. A resolving
// doclint:enforced-by excuses one burden phrase: the last one of the sentence it ends (or, alone on
// its line, the first one of the sentence on the next line). Code spans may wrap across the lines
// of a paragraph. Lines inside the caller's fenced blocks must already have been blanked.
func ScanText(w *Workspace, file string, first int, lines []string) []Finding {
	var out []Finding
	for start := 0; start < len(lines); {
		if strings.TrimSpace(lines[start]) == "" {
			start++
			continue
		}
		end := start + 1
		for end < len(lines) && strings.TrimSpace(lines[end]) != "" && !blockStartRe.MatchString(lines[end]) {
			end++
		}
		out = append(out, scanParagraph(w, file, first+start, lines[start:end])...)
		out = append(out, scanSymbols(w, file, first+start, lines[start:end])...)
		start = end
	}
	for i, line := range lines {
		out = append(out, scanBannedLinks(file, first+i, line)...)
	}
	slices.SortStableFunc(out, func(a, b Finding) int { return cmp.Compare(a.Line, b.Line) })
	return out
}

func scanParagraph(w *Workspace, file string, first int, para []string) []Finding {
	var out []Finding
	marked := make([]string, len(para))
	alone := make([]bool, len(para))
	for i, raw := range para {
		l := sanitize(raw)
		alone[i] = enforcedByRe.MatchString(l) && isEscapeOnly(l)
		marked[i] = enforcedByRe.ReplaceAllStringFunc(l, func(m string) string {
			s := enforcedByRe.FindStringSubmatch(m)
			if w.ResolveTest(s[1], s[2], s[3]) {
				return string(escMark)
			}
			out = append(out, Finding{Rule: RuleEnforced, File: file, Line: first + i,
				Message: "doclint:enforced-by target " + quote(strings.TrimSpace(strings.TrimPrefix(m, "doclint:enforced-by"))) + " is not a resolving Test, Example, Benchmark, Fuzz function or suite"})
			return " "
		})
	}
	flagged := map[int]bool{}
	claimed := map[int]bool{}
	for _, v := range views(marked) {
		ms := v.burdens()
		excused := v.excused(ms, alone)
		for i, m := range ms {
			line := lineAt(v.starts, m[0])
			if flagged[line] || excused[i] {
				continue
			}
			flagged[line] = true
			out = append(out, Finding{Rule: RuleBurden, File: file, Line: first + line,
				Message: "burden sentence " + quote(excerpt(v.text[m[0]:m[1]])) + ": make the misuse unrepresentable or add doclint:enforced-by <pkg.Test>"})
		}
		out = append(out, v.claims(file, first, claimed)...)
	}
	return out
}

func (v view) burdens() [][]int {
	var ms [][]int
	for _, re := range burdenPatterns {
		ms = append(ms, re.FindAllStringIndex(v.text, -1)...)
	}
	slices.SortStableFunc(ms, func(a, b []int) int { return cmp.Compare(a[0], b[0]) })
	return ms
}

func (v view) excused(ms [][]int, alone []bool) []bool {
	out := make([]bool, len(ms))
	for _, e := range v.escapes(alone) {
		anchor := -1
		for i, m := range ms {
			if v.sentenceOf(m[0]) != e.sentence {
				continue
			}
			if !e.before && m[0] < e.at {
				anchor = i
				continue
			}
			if anchor < 0 {
				anchor = i
			}
			break
		}
		if anchor < 0 {
			continue
		}
		a := ms[anchor]
		for i, m := range ms {
			if v.sentenceOf(m[0]) == e.sentence && m[0] < a[1] && a[0] < m[1] {
				out[i] = true
			}
		}
	}
	return out
}

func scanClaims(file string, first int, lines []string) []Finding {
	clean := make([]string, len(lines))
	for i, l := range lines {
		clean[i] = sanitize(l)
	}
	var out []Finding
	claimed := map[int]bool{}
	for _, v := range views(clean) {
		out = append(out, v.claims(file, first, claimed)...)
	}
	return out
}

func (v view) claims(file string, first int, claimed map[int]bool) []Finding {
	var out []Finding
	for _, loc := range bannedClaim.FindAllStringIndex(v.text, -1) {
		line := lineAt(v.starts, loc[0])
		if claimed[line] {
			continue
		}
		claimed[line] = true
		out = append(out, Finding{Rule: RuleBanned, File: file, Line: first + line,
			Message: "banned claim \"Signatures verified against source\""})
	}
	return out
}

func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if r != '\t' && unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
}

func views(lines []string) []view {
	raw, tagged := encode(lines, false), encode(lines, true)
	var out []view
	for _, comments := range []int{keepComments, dropComments, spaceComments} {
		out = append(out, newView(project(raw, comments, false)))
		for _, tagSpace := range []bool{false, true} {
			out = append(out, newView(project(tagged, comments, tagSpace)))
		}
	}
	return out
}

func encode(lines []string, tags bool) string {
	pre := make([]string, len(lines))
	for i, l := range lines {
		pre[i] = trimHardBreak(strings.TrimLeft(strings.TrimSpace(l), "> \t"))
	}
	joined := htmlCommentRe.ReplaceAllStringFunc(strings.Join(pre, "\n"), func(c string) string {
		inner := ""
		if c != "<!-->" && c != "<!--->" {
			inner = c[len("<!--") : len(c)-len("-->")]
		}
		return string(openMark) + inner + string(closeMark)
	})
	if tags {
		joined = htmlTagRe.ReplaceAllStringFunc(joined, func(t string) string {
			return string(tagMark) + strings.Repeat("\n", strings.Count(t, "\n"))
		})
	}
	parts := strings.Split(joined, "\n")
	for i, p := range parts {
		parts[i] = rendered(p)
	}
	return strings.Join(parts, "\n")
}

func trimHardBreak(s string) string {
	n := len(s) - len(strings.TrimRight(s, "\\"))
	if n%2 == 1 {
		return s[:len(s)-1]
	}
	return s
}

func project(s string, mode int, tagSpace bool) string {
	var b strings.Builder
	in := false
	pending := 0
	flush := func() {
		b.WriteString(strings.Repeat("\n", pending))
		pending = 0
	}
	for _, r := range s {
		if pending > 0 && (r == ' ' || r == '\n') && !in {
			flush()
		}
		switch {
		case in && mode == dropComments && r == '\n':
			pending++
		case r == tagMark:
			if tagSpace && (!in || mode == keepComments) {
				b.WriteByte(' ')
			}
		case r == openMark:
			in = true
			if mode != dropComments {
				b.WriteByte(' ')
			}
		case r == closeMark:
			in = false
			if mode == keepComments {
				b.WriteByte(' ')
			}
		case in && mode != keepComments && r != '\n' && r != escMark:
		default:
			b.WriteRune(r)
		}
	}
	flush()
	return b.String()
}

func newView(s string) view {
	v := view{starts: []int{0}}
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case escMark:
			v.marks = append(v.marks, i)
		case '\n':
			v.starts = append(v.starts, i+1)
		}
	}
	v.text = strings.ReplaceAll(s, string(escMark), " ")
	for i := 0; i < len(v.text); i++ {
		if c := v.text[i]; c == '.' || c == '!' || c == '?' {
			rest := strings.TrimLeft(v.text[i+1:], ")\"'’”»")
			if rest == "" || rest[0] == ' ' || rest[0] == '\n' {
				v.breaks = append(v.breaks, i)
			}
		}
	}
	return v
}

func (v view) sentenceOf(off int) int {
	i, _ := slices.BinarySearch(v.breaks, off)
	return i
}

type escape struct {
	sentence int
	at       int
	before   bool
}

func (v view) escapes(alone []bool) []escape {
	var out []escape
	for _, p := range v.marks {
		li := lineAt(v.starts, p)
		if li < len(alone) && alone[li] && li+1 < len(v.starts) {
			if q := v.nextContent(v.starts[li+1]); q >= 0 {
				out = append(out, escape{sentence: v.sentenceOf(q), at: p, before: true})
				continue
			}
		}
		if q := v.prevContent(p); q >= 0 {
			out = append(out, escape{sentence: v.sentenceOf(q), at: p})
		} else if q := v.nextContent(p); q >= 0 {
			out = append(out, escape{sentence: v.sentenceOf(q), at: p, before: true})
		}
	}
	return out
}

func (v view) prevContent(p int) int {
	for i := p - 1; i >= 0; i-- {
		if v.text[i] != ' ' && v.text[i] != '\n' {
			return i
		}
	}
	return -1
}

func (v view) nextContent(p int) int {
	for i := p; i < len(v.text); i++ {
		if v.text[i] != ' ' && v.text[i] != '\n' {
			return i
		}
	}
	return -1
}

func rendered(s string) string {
	s = footnoteRe.ReplaceAllString(s, "")
	s = stripLinkDests(s)
	s = linkRefRe.ReplaceAllString(s, "")
	s = mdEscapeRe.ReplaceAllString(s, "$1")
	s = markupChars.Replace(s)
	s = html.UnescapeString(s)
	return strings.Map(func(r rune) rune {
		switch {
		case r == escMark || r == openMark || r == closeMark || r == tagMark:
			return r
		case unicode.IsSpace(r):
			return ' '
		case unicode.Is(unicode.Cf, r), unicode.IsControl(r):
			return -1
		case r >= 0xFF01 && r <= 0xFF5E:
			return r - 0xFEE0
		case r >= 0x1D400 && r <= 0x1D6A3:
			o := (r - 0x1D400) % 52
			if o < 26 {
				return 'A' + o
			}
			return 'a' + o - 26
		case r >= 0x1D7CE && r <= 0x1D7FF:
			return '0' + (r-0x1D7CE)%10
		}
		if f, ok := confusables[r]; ok {
			return f
		}
		return r
	}, s)
}

func isEscapeOnly(line string) bool {
	rest := escapeOnly.Replace(enforcedByRe.ReplaceAllString(line, ""))
	return strings.Trim(rest, " \t>*-+/.") == ""
}

func lineAt(starts []int, off int) int {
	i, found := slices.BinarySearch(starts, off)
	if found {
		return i
	}
	return i - 1
}

func scanSymbols(w *Workspace, file string, first int, para []string) []Finding {
	text := strings.Join(para, "\n")
	type ref struct {
		line int
		text string
	}
	var refs []ref
	add := func(off int, s string) {
		refs = append(refs, ref{line: first + strings.Count(text[:off], "\n"), text: strings.ReplaceAll(s, "\n", " ")})
	}
	for _, m := range backtickRe.FindAllStringSubmatchIndex(text, -1) {
		add(m[0], text[m[2]:m[3]])
	}
	for _, m := range codeTagRe.FindAllStringSubmatchIndex(text, -1) {
		add(m[0], html.UnescapeString(text[m[2]:m[3]]))
	}
	for _, m := range docLinkRe.FindAllStringSubmatchIndex(text, -1) {
		add(m[0], text[m[2]:m[3]])
	}
	var out []Finding
	seen := map[string]bool{}
	for _, r := range refs {
		matches := symbolRe.FindAllStringSubmatchIndex(r.text, -1)
		for _, s := range glueSymbolRe.FindAllStringSubmatchIndex(r.text, -1) {
			if w.HasPackage(r.text[s[2]:s[3]]) {
				matches = append(matches, s)
			}
		}
		for _, s := range matches {
			pkg, chain := r.text[s[2]:s[3]], braceRe.ReplaceAllString(r.text[s[4]:s[5]], "")
			sym := pkg + "." + chain
			key := strconv.Itoa(r.line) + " " + sym
			if seen[key] {
				continue
			}
			seen[key] = true
			if !w.Resolve(pkg, selectors(chain, parenthesized(r.text[:s[2]]))...) {
				out = append(out, Finding{Rule: RuleSymbol, File: file, Line: r.line,
					Message: "symbol reference " + quote(sym) + " in " + quote(r.text) + " does not resolve to an exported API symbol"})
			}
		}
	}
	return out
}

func parenthesized(before string) bool {
	before = strings.TrimSuffix(before, "*")
	rest, ok := strings.CutSuffix(before, "(")
	if !ok {
		return false
	}
	r, _ := utf8.DecodeLastRuneInString(rest)
	return rest == "" || (!unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' && r != ']' && r != ')')
}

func selectors(chain string, closes bool) []string {
	var path []string
	for _, piece := range strings.Split(chain, ".") {
		m := selectorRe.FindStringSubmatch(piece)
		if m == nil {
			break
		}
		el := m[1]
		if m[2] != "" {
			el += "()"
		}
		path = append(path, el)
		if m[3] != "" && !closes {
			break
		}
	}
	return path
}

func scanBannedLinks(file string, no int, line string) []Finding {
	cands := []string{line}
	for range 2 {
		next := slices.Clone(cands)
		for _, c := range cands {
			for _, d := range []string{html.UnescapeString(c), mdEscapeRe.ReplaceAllString(c, "$1"), percentDecode(c), htmlTagRe.ReplaceAllString(c, ""), spacedAngleDest(c)} {
				if !slices.Contains(next, d) {
					next = append(next, d)
				}
			}
		}
		cands = next
	}
	for _, c := range cands {
		if m := bannedLinkRe.FindStringSubmatch(c); m != nil {
			return []Finding{{Rule: RuleBanned, File: file, Line: no, Message: "banned reference " + quote(m[1])}}
		}
	}
	return nil
}

func percentDecode(s string) string {
	return percentRe.ReplaceAllStringFunc(s, func(m string) string {
		b, err := strconv.ParseUint(m[1:], 16, 8)
		if err != nil {
			return m
		}
		return string(rune(b))
	})
}

func excerpt(s string) string {
	s = spaceRe.ReplaceAllString(s, " ")
	if r := []rune(s); len(r) > 60 {
		return string(r[:28]) + " ... " + string(r[len(r)-28:])
	}
	return s
}

func quote(s string) string { return "\"" + s + "\"" }

func spacedAngleDest(s string) string {
	return angleDestRe.ReplaceAllStringFunc(s, func(m string) string {
		return strings.Map(func(r rune) rune {
			if unicode.IsSpace(r) {
				return '-'
			}
			return r
		}, m)
	})
}

func stripLinkDests(s string) string {
	var b strings.Builder
	for {
		i := strings.Index(s, "](")
		if i < 0 {
			b.WriteString(s)
			return b.String()
		}
		b.WriteString(s[:i])
		end := linkDestEnd(s, i+2)
		if end < 0 {
			loc := linkDestRe.FindStringIndex(s[i:])
			if loc == nil {
				b.WriteString(s[i:])
				return b.String()
			}
			end = i + loc[1]
		}
		s = s[end:]
	}
}

func linkDestEnd(s string, i int) int {
	i = skipSpaces(s, i)
	if i < len(s) && s[i] == '<' {
		i = scanTo(s, i+1, '>')
		if i < 0 {
			return -1
		}
	} else {
		depth := 0
	dest:
		for ; i < len(s); i++ {
			switch c := s[i]; {
			case c == '\\':
				i++
			case c == '(':
				depth++
			case c == ')' && depth == 0:
				return i + 1
			case c == ')':
				depth--
			case c == ' ' || c == '\t':
				break dest
			}
		}
	}
	i = skipSpaces(s, i)
	if i >= len(s) {
		return -1
	}
	switch s[i] {
	case ')':
		return i + 1
	case '"', '\'':
		i = scanTo(s, i+1, s[i])
	case '(':
		i = scanTo(s, i+1, ')')
	default:
		return -1
	}
	if i < 0 {
		return -1
	}
	i = skipSpaces(s, i)
	if i < len(s) && s[i] == ')' {
		return i + 1
	}
	return -1
}

func skipSpaces(s string, i int) int {
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	return i
}

func scanTo(s string, i int, closer byte) int {
	for ; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case closer:
			return i + 1
		}
	}
	return -1
}
