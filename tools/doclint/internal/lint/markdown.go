package lint

import (
	"go/ast"
	"go/parser"
	"go/token"
	"html"
	"regexp"
	"slices"
	"strings"
)

var (
	embedRe   = regexp.MustCompile(`^<!--\s*embed:\s*(\S+?)#(\w+)\s*-->$`)
	fenceRe   = regexp.MustCompile("^(```+|~~~+)[ \t]*(.*)$")
	quoteRe   = regexp.MustCompile(`^[ \t]*>[ \t]?`)
	listRe    = regexp.MustCompile(`^[ \t]*(?:[-*+]|\d{1,9}[.)])[ \t]+`)
	preRe     = regexp.MustCompile(`(?is)<pre\b([^>]*)>(.*?)(?:</pre\s*>|\z)`)
	codeOpen  = regexp.MustCompile(`(?i)<code\b[^>]*>`)
	goClassRe = regexp.MustCompile(`(?i)\b(?:language|lang)-(?:go|golang)\b|\blang\s*=\s*["']?(?:go|golang)\b`)
	elisions  = []struct {
		re   *regexp.Regexp
		with string
	}{
		{regexp.MustCompile(`(?m)^[ \t]*(?://[ \t]*)?\.\.\.[ \t]*$`), ""},
		{regexp.MustCompile(`\(\s*\.\.\.\s*\)`), "()"},
		{regexp.MustCompile(`\{\s*\.\.\.\s*\}`), "{}"},
		{regexp.MustCompile(`,\s*\.\.\.\s*([)}\]])`), "$1"},
	}
)

const (
	missingMarker  = "fenced Go block lacks a preceding <!-- embed: <file>#<ExampleName> --> marker"
	htmlGoBlock    = "Go code in an HTML <pre>/<code> block cannot be embedded; use a fenced Go block preceded by <!-- embed: <file>#<ExampleName> -->"
	indentedGoCode = "Go code in an indented code block cannot be embedded; use a fenced Go block preceded by <!-- embed: <file>#<ExampleName> -->"
)

type fence struct {
	marker string
	info   string
	quotes int
	indent int
	cont   string
}

// ScanMarkdown applies G26 to the prose of a Markdown file (G26c also to fenced blocks) and G27 to
// its fenced Go blocks: blocks whose info string spells go or golang in any case, untagged blocks
// whose content parses as Go, and blocks tagged with another language whose content is
// unmistakably Go (a package clause, a func, type or import declaration, or a := statement).
// Content is also tried with "..." elisions removed. Go code in an HTML <pre> or <code> block or
// in an indented code block is always reported, as it cannot be regenerated. Fences opened inside
// blockquotes and list items count, and such a fence ends with its container. When regenerate is
// true the returned text has every embedded block rewritten from its source example, keeping the
// container prefix; otherwise it equals content. Embedded blocks that differ from their source
// are reported as findings only when regenerate is false.
func ScanMarkdown(w *Workspace, file, content string, regenerate bool) (string, []Finding) {
	lines := strings.Split(content, "\n")
	var findings []Finding
	var prose []string
	var out []string
	for i := 0; i < len(lines); i++ {
		f, ok := openFence(lines[i])
		if !ok {
			prose = append(prose, lines[i])
			out = append(out, lines[i])
			continue
		}
		end, closed := f.span(lines, i)
		for j := i; j <= end; j++ {
			findings = append(findings, scanBannedLinks(file, j+1, lines[j])...)
			prose = append(prose, "")
		}
		findings = append(findings, scanClaims(file, i+1, lines[i:end+1])...)
		block := lines[i : end+1]
		body := f.body(lines, i, end, closed)
		src := strings.Join(body, "\n")
		isGo := isGoInfo(f.info) || (f.info == "" && looksLikeGo(src)) || (f.info != "" && looksLikeGoSource(src))
		if isGo && !closed {
			findings = append(findings, Finding{Rule: RuleEmbed, File: file, Line: i + 1, Message: "unterminated fenced Go block"})
		} else if isGo {
			var fs []Finding
			block, fs = checkEmbed(w, file, lines, f, i, end, regenerate)
			findings = append(findings, fs...)
		}
		out = append(out, block...)
		i = end
	}
	findings = append(findings, ScanText(w, file, 1, prose)...)
	findings = append(findings, scanHTMLGo(file, prose)...)
	findings = append(findings, scanIndentedGo(file, prose)...)
	slices.SortStableFunc(findings, func(a, b Finding) int { return a.Line - b.Line })
	return strings.Join(out, "\n"), findings
}

func openFence(line string) (fence, bool) {
	rest := line
	quotes, afterQuote, list := 0, 0, false
	for {
		if m := quoteRe.FindString(rest); m != "" {
			quotes++
			rest = rest[len(m):]
			afterQuote = len(line) - len(rest)
			list = false
			continue
		}
		if m := listRe.FindString(rest); m != "" {
			rest = rest[len(m):]
			list = true
			continue
		}
		break
	}
	trimmed := strings.TrimLeft(rest, " \t")
	m := fenceRe.FindStringSubmatch(trimmed)
	if m == nil || (m[1][0] == '`' && strings.Contains(m[2], "`")) {
		return fence{}, false
	}
	prefix := line[:len(line)-len(trimmed)]
	f := fence{marker: m[1], info: strings.TrimSpace(m[2]), quotes: quotes, indent: -1, cont: continuation(prefix)}
	if list {
		f.indent = len(prefix) - afterQuote
	}
	return f, true
}

func continuation(prefix string) string {
	return strings.Map(func(r rune) rune {
		if r == '>' || r == ' ' || r == '\t' {
			return r
		}
		return ' '
	}, prefix)
}

func (f fence) inside(line string) (string, bool) {
	rest := line
	for range f.quotes {
		m := quoteRe.FindString(rest)
		if m == "" {
			return "", false
		}
		rest = rest[len(m):]
	}
	if f.indent >= 0 && strings.TrimSpace(rest) != "" && indentWidth(rest) < f.indent {
		return "", false
	}
	return rest, true
}

func indentWidth(s string) int {
	n := 0
	for _, r := range s {
		switch r {
		case ' ':
			n++
		case '\t':
			n += 4 - n%4
		default:
			return n
		}
	}
	return n
}

func (f fence) span(lines []string, open int) (int, bool) {
	for j := open + 1; j < len(lines); j++ {
		rest, ok := f.inside(lines[j])
		if !ok {
			return j - 1, false
		}
		t := strings.TrimSpace(rest)
		if strings.HasPrefix(t, f.marker) && strings.Trim(t, f.marker[:1]) == "" {
			return j, true
		}
	}
	return len(lines) - 1, false
}

func (f fence) body(lines []string, open, end int, closed bool) []string {
	last := end + 1
	if closed {
		last = end
	}
	var out []string
	for _, l := range lines[open+1 : last] {
		rest, _ := f.inside(l)
		out = append(out, rest)
	}
	return out
}

func isGoInfo(info string) bool {
	info = strings.TrimLeft(info, "{.")
	n := 0
	for n < len(info) && (info[n]|0x20 >= 'a' && info[n]|0x20 <= 'z') {
		n++
	}
	lang := strings.ToLower(info[:n])
	return lang == "go" || lang == "golang"
}

func looksLikeGo(src string) bool {
	return parsesAsGo(src) || withElisions(src, parsesAsGo)
}

func looksLikeGoSource(src string) bool {
	return parsesAsGoSource(src) || withElisions(src, parsesAsGoSource)
}

func withElisions(src string, parses func(string) bool) bool {
	elided := src
	for _, e := range elisions {
		elided = e.re.ReplaceAllString(elided, e.with)
	}
	return elided != src && parses(elided)
}

func parsesAsGo(src string) bool {
	if strings.TrimSpace(src) == "" {
		return false
	}
	fset := token.NewFileSet()
	if _, err := parser.ParseFile(fset, "", src, parser.SkipObjectResolution); err == nil {
		return true
	}
	if f, err := parser.ParseFile(fset, "", "package p\n"+src, parser.SkipObjectResolution); err == nil && len(f.Decls) > 0 {
		return true
	}
	f, err := parser.ParseFile(fset, "", "package p\nfunc _() {\n"+src+"\n}", parser.SkipObjectResolution)
	if err != nil || len(f.Decls) != 1 {
		return false
	}
	fn, ok := f.Decls[0].(*ast.FuncDecl)
	if !ok || fn.Body == nil {
		return false
	}
	return slices.ContainsFunc(fn.Body.List, isGoStatement)
}

func parsesAsGoSource(src string) bool {
	if strings.TrimSpace(src) == "" {
		return false
	}
	fset := token.NewFileSet()
	if _, err := parser.ParseFile(fset, "", src, parser.SkipObjectResolution); err == nil {
		return true
	}
	if f, err := parser.ParseFile(fset, "", "package p\n"+src, parser.SkipObjectResolution); err == nil && slices.ContainsFunc(f.Decls, isGoOnlyDecl) {
		return true
	}
	f, err := parser.ParseFile(fset, "", "package p\nfunc _() {\n"+src+"\n}", parser.SkipObjectResolution)
	if err != nil || len(f.Decls) != 1 {
		return false
	}
	fn, ok := f.Decls[0].(*ast.FuncDecl)
	if !ok || fn.Body == nil {
		return false
	}
	return slices.ContainsFunc(fn.Body.List, func(s ast.Stmt) bool {
		a, ok := s.(*ast.AssignStmt)
		return ok && a.Tok == token.DEFINE
	})
}

func isGoOnlyDecl(d ast.Decl) bool {
	switch d := d.(type) {
	case *ast.FuncDecl:
		return true
	case *ast.GenDecl:
		return d.Tok == token.IMPORT || d.Tok == token.TYPE
	}
	return false
}

func scanHTMLGo(file string, prose []string) []Finding {
	text := strings.Join(prose, "\n")
	var out []Finding
	var covered [][]int
	for _, m := range preRe.FindAllStringSubmatchIndex(text, -1) {
		attrs := text[m[2]:m[3]] + " " + strings.Join(codeOpen.FindAllString(text[m[4]:m[5]], -1), " ")
		content := html.UnescapeString(htmlTagRe.ReplaceAllString(text[m[4]:m[5]], ""))
		if goClassRe.MatchString(attrs) || looksLikeGo(content) {
			covered = append(covered, m[:2])
			out = append(out, Finding{Rule: RuleEmbed, File: file, Line: 1 + strings.Count(text[:m[0]], "\n"), Message: htmlGoBlock})
		}
	}
	for _, m := range codeOpen.FindAllStringIndex(text, -1) {
		inside := slices.ContainsFunc(covered, func(c []int) bool { return m[0] >= c[0] && m[0] < c[1] })
		if !inside && goClassRe.MatchString(text[m[0]:m[1]]) {
			out = append(out, Finding{Rule: RuleEmbed, File: file, Line: 1 + strings.Count(text[:m[0]], "\n"), Message: htmlGoBlock})
		}
	}
	return out
}

func scanIndentedGo(file string, prose []string) []Finding {
	var out []Finding
	for i := 0; i < len(prose); i++ {
		if !isIndentedCode(prose[i]) || (i > 0 && strings.TrimSpace(prose[i-1]) != "") {
			continue
		}
		start := i
		var body []string
		for ; i < len(prose) && (strings.TrimSpace(prose[i]) == "" || isIndentedCode(prose[i])); i++ {
			body = append(body, dedentCode(prose[i]))
		}
		if looksLikeGo(strings.Join(body, "\n")) {
			out = append(out, Finding{Rule: RuleEmbed, File: file, Line: start + 1, Message: indentedGoCode})
		}
	}
	return out
}

func isIndentedCode(line string) bool {
	return strings.TrimSpace(line) != "" && indentWidth(line) >= 4
}

func dedentCode(line string) string {
	if rest, ok := strings.CutPrefix(line, "\t"); ok {
		return rest
	}
	n := 0
	for n < 4 && n < len(line) && line[n] == ' ' {
		n++
	}
	if n < 4 && n < len(line) && line[n] == '\t' {
		n++
	}
	return line[n:]
}

func isGoStatement(s ast.Stmt) bool {
	switch s := s.(type) {
	case *ast.AssignStmt:
		return s.Tok == token.DEFINE
	case *ast.ExprStmt:
		call, ok := s.X.(*ast.CallExpr)
		if !ok {
			return false
		}
		_, sel := call.Fun.(*ast.SelectorExpr)
		return sel
	case *ast.IfStmt, *ast.ForStmt, *ast.RangeStmt, *ast.SwitchStmt, *ast.TypeSwitchStmt, *ast.SelectStmt,
		*ast.ReturnStmt, *ast.DeferStmt, *ast.GoStmt, *ast.DeclStmt:
		return true
	}
	return false
}

func checkEmbed(w *Workspace, file string, lines []string, f fence, open, end int, regenerate bool) ([]string, []Finding) {
	block := lines[open : end+1]
	marker := previousContent(lines, open)
	if marker < 0 {
		return block, []Finding{{Rule: RuleEmbed, File: file, Line: open + 1, Message: missingMarker}}
	}
	m := embedRe.FindStringSubmatch(containerContent(lines[marker]))
	if m == nil {
		return block, []Finding{{Rule: RuleEmbed, File: file, Line: open + 1, Message: missingMarker}}
	}
	body, err := w.Example(m[1], m[2])
	if err != nil {
		return block, []Finding{{Rule: RuleEmbed, File: file, Line: marker + 1, Message: err.Error()}}
	}
	want := []string{lines[open]}
	for _, l := range strings.Split(body, "\n") {
		if l == "" {
			want = append(want, strings.TrimRight(f.cont, " \t"))
			continue
		}
		want = append(want, f.cont+l)
	}
	want = append(want, lines[end])
	if slices.Equal(block, want) {
		return block, nil
	}
	if regenerate {
		return want, nil
	}
	return block, []Finding{{Rule: RuleEmbed, File: file, Line: open + 1, Message: "embedded block differs from " + m[1] + "#" + m[2] + "; run doclint -write"}}
}

func containerContent(line string) string {
	rest := line
	for {
		if m := quoteRe.FindString(rest); m != "" {
			rest = rest[len(m):]
			continue
		}
		if m := listRe.FindString(rest); m != "" {
			rest = rest[len(m):]
			continue
		}
		return strings.TrimSpace(rest)
	}
}

func previousContent(lines []string, before int) int {
	for j := before - 1; j >= 0; j-- {
		if containerContent(lines[j]) != "" {
			return j
		}
	}
	return -1
}
