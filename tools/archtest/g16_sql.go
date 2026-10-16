package archtest

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

type sqlStatement struct {
	text string
	code string
	line int
}

var dollarQuote = regexp.MustCompile(`^\$([A-Za-z_][A-Za-z0-9_]*)?\$`)

func splitSQL(src string) []sqlStatement {
	var out []sqlStatement
	var text, code strings.Builder
	line, start := 1, 1
	flush := func() {
		if t := strings.TrimSpace(text.String()); t != "" {
			out = append(out, sqlStatement{text: t, code: code.String(), line: start})
		}
		text.Reset()
		code.Reset()
	}
	emit := func(s string, inCode bool) {
		if strings.TrimSpace(text.String()) == "" && strings.TrimSpace(s) != "" {
			start = line
		}
		text.WriteString(s)
		if inCode {
			code.WriteString(s)
		} else {
			code.WriteString("''")
		}
		line += strings.Count(s, "\n")
	}
	for i := 0; i < len(src); {
		rest := src[i:]
		switch {
		case strings.HasPrefix(rest, "--"):
			end := strings.IndexByte(rest, '\n')
			if end < 0 {
				end = len(rest)
			}
			i += end
		case strings.HasPrefix(rest, "/*"):
			end := strings.Index(rest, "*/")
			if end < 0 {
				end = len(rest) - 2
			}
			line += strings.Count(rest[:end+2], "\n")
			i += end + 2
		case rest[0] == '\'':
			escapes := escapeStringPrefix(src[:i])
			end := 1
			for end < len(rest) {
				if escapes && rest[end] == '\\' {
					end += 2
					continue
				}
				if rest[end] == '\'' {
					if end+1 < len(rest) && rest[end+1] == '\'' {
						end += 2
						continue
					}
					break
				}
				end++
			}
			if end >= len(rest) {
				end = len(rest) - 1
			}
			emit(rest[:end+1], false)
			i += end + 1
		case rest[0] == '$' && dollarQuote.MatchString(rest):
			delim := dollarQuote.FindString(rest)
			end := strings.Index(rest[len(delim):], delim)
			if end < 0 {
				end = len(rest) - len(delim)
			}
			total := len(delim) + end + len(delim)
			if total > len(rest) {
				total = len(rest)
			}
			emit(rest[:total], true)
			i += total
		case rest[0] == ';':
			flush()
			i++
		default:
			emit(rest[:1], true)
			i++
		}
	}
	flush()
	return out
}

func escapeStringPrefix(before string) bool {
	n := len(before)
	if n == 0 || (before[n-1] != 'E' && before[n-1] != 'e') {
		return false
	}
	if n == 1 {
		return true
	}
	c := before[n-2]
	return c != '_' && c != '$' && (c < '0' || c > '9') && (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && c < 0x80
}

const duplicateCondition = `DUPLICATE_(OBJECT|TABLE|COLUMN|SCHEMA|FUNCTION)`

var guardWords = map[string]bool{
	"IN": true, "EXISTS": true, "ANY": true, "ALL": true, "NOT": true, "AND": true, "OR": true, "ON": true,
	"WHERE": true, "SELECT": true, "FROM": true, "JOIN": true, "USING": true,
	"TO_REGCLASS": true, "TO_REGTYPE": true, "TO_REGNAMESPACE": true, "CURRENT_SCHEMA": true, "LOWER": true, "UPPER": true,
}

const sqlName = `(?:"(?:[^"]|"")*"|[^ ".(),;]+)(?:\.(?:"(?:[^"]|"")*"|[^ ".(),;]+))*`

var (
	spaces      = regexp.MustCompile(`\s+`)
	dropWord    = regexp.MustCompile(`\bDROP\b`)
	createOK    = regexp.MustCompile(`^CREATE (UNLOGGED |TEMP |TEMPORARY )?TABLE IF NOT EXISTS |^CREATE (UNIQUE )?INDEX (CONCURRENTLY )?IF NOT EXISTS |^CREATE (EXTENSION|SEQUENCE|SCHEMA) IF NOT EXISTS `)
	alterTable  = regexp.MustCompile(`^ALTER TABLE (IF EXISTS )?(ONLY )?` + sqlName + ` (.*)$`)
	addColumnOK = regexp.MustCompile(`^ADD COLUMN IF NOT EXISTS `)
	doBlock     = regexp.MustCompile(`^DO (LANGUAGE [A-Z_]+ )?\$`)
	doSource    = regexp.MustCompile(`(?is)^DO\s+(?:LANGUAGE\s+[a-z_]+\s+)?(\$[a-z_]*\$)(.*)(\$[a-z_]*\$)\s*(?:LANGUAGE\s+[a-z_]+)?$`)
	doHandler   = regexp.MustCompile(`^EXCEPTION WHEN ` + duplicateCondition + `( OR ` + duplicateCondition + `)* THEN NULL$`)
	createTable = regexp.MustCompile(`^CREATE (UNLOGGED |TEMP |TEMPORARY )?TABLE (IF NOT EXISTS )?` + sqlName + ` ?`)
	asClause    = regexp.MustCompile(`(^| )AS( |$)`)
	quotedCall  = regexp.MustCompile(`" ?\(`)
	callSite    = regexp.MustCompile(`([A-Z_][A-Z0-9_$]*(?:\.[A-Z_][A-Z0-9_$]*)?) ?\(`)
	fromWord    = regexp.MustCompile(`\bFROM `)
	fromEnd     = regexp.MustCompile(`^ (WHERE|GROUP|HAVING|ORDER|LIMIT|OFFSET|UNION|EXCEPT|INTERSECT|WINDOW|FOR) `)
	joinSep     = regexp.MustCompile(`,| (?:(?:LEFT|RIGHT|FULL|INNER|CROSS|NATURAL)(?: OUTER)? )?JOIN `)
	catalogRel  = regexp.MustCompile(`^((PG_CATALOG\.)?PG_[A-Z0-9_]+|INFORMATION_SCHEMA\.[A-Z0-9_]+)$`)
	guardedWork = regexp.MustCompile(`^(CREATE (UNIQUE )?INDEX |CREATE (UNLOGGED )?TABLE |CREATE (TYPE|SEQUENCE|SCHEMA|EXTENSION|DOMAIN) |ALTER TYPE ` + sqlName + ` ADD VALUE |COMMENT ON |NULL$)`)
	guardedAdd  = regexp.MustCompile(`^ADD (CONSTRAINT|COLUMN) `)
)

func normaliseSQL(s string) string {
	return strings.ToUpper(spaces.ReplaceAllString(strings.TrimSpace(s), " "))
}

func splitTopLevel(s string) []string {
	var out []string
	depth, start := 0, 0
	var quote rune
	for i, r := range s {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			}
		case r == '"' || r == '\'':
			quote = r
		case r == '(':
			depth++
		case r == ')':
			depth--
		case r == ',' && depth == 0:
			out = append(out, strings.TrimSpace(s[start:i]))
			start = i + 1
		}
	}
	return append(out, strings.TrimSpace(s[start:]))
}

func statementProblem(st sqlStatement) string {
	code := normaliseSQL(st.code)
	if dropWord.MatchString(code) {
		return "DROP is forbidden in a v0.17 migration"
	}
	norm := normaliseSQL(st.text)
	switch {
	case createOK.MatchString(code):
		if isCreateTableAs(code) {
			return "CREATE TABLE ... AS runs a query in a migration: " + clip(norm)
		}
		return ""
	case doBlock.MatchString(norm):
		return doBlockProblem(st.text)
	}
	if m := alterTable.FindStringSubmatch(code); m != nil {
		for _, action := range splitTopLevel(m[3]) {
			if !addColumnOK.MatchString(action) {
				return "ALTER TABLE action outside ADD COLUMN IF NOT EXISTS: " + clip(action)
			}
		}
		return ""
	}
	return "statement outside the idempotent allowlist: " + clip(norm)
}

const doShape = "DO block outside the guarded allowlist (BEGIN IF [NOT] EXISTS (SELECT ...) THEN <DDL>; END IF; ... END, or BEGIN <DDL>; ... EXCEPTION WHEN <condition> THEN NULL; END)"

func doBlockProblem(text string) string {
	m := doSource.FindStringSubmatch(strings.TrimSpace(text))
	if m == nil || m[1] != m[3] {
		return doShape
	}
	var stmts []string
	for _, st := range splitSQL(m[2]) {
		stmts = append(stmts, normaliseSQL(st.code))
	}
	if len(stmts) < 2 || stmts[len(stmts)-1] != "END" {
		return doShape
	}
	first, ok := strings.CutPrefix(stmts[0], "BEGIN ")
	if !ok {
		return doShape
	}
	body := append([]string{first}, stmts[1:len(stmts)-1]...)
	if h := body[len(body)-1]; strings.HasPrefix(h, "EXCEPTION ") {
		if !doHandler.MatchString(h) || len(body) < 2 {
			return doShape
		}
		for _, w := range body[:len(body)-1] {
			if !guardedWorkOK(w) {
				return doShape
			}
		}
		return ""
	}
	for i := 0; i < len(body); {
		work, ok := ifExistsGuard(body[i])
		if !ok {
			return doShape
		}
		i++
		works := 0
		for work != "END IF" {
			if !guardedWorkOK(work) || i >= len(body) {
				return doShape
			}
			works++
			work = body[i]
			i++
		}
		if works == 0 {
			return doShape
		}
	}
	return ""
}

func ifExistsGuard(s string) (string, bool) {
	rest, ok := strings.CutPrefix(s, "IF ")
	if !ok {
		return "", false
	}
	rest = strings.TrimPrefix(rest, "NOT ")
	rest, ok = strings.CutPrefix(rest, "EXISTS (SELECT ")
	if !ok {
		return "", false
	}
	depth := 1
	for i, r := range rest {
		switch r {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				if !guardSelectOK("SELECT " + rest[:i]) {
					return "", false
				}
				work, ok := strings.CutPrefix(rest[i+1:], " THEN ")
				return work, ok
			}
		}
	}
	return "", false
}

func guardSelectOK(sel string) bool {
	if quotedCall.MatchString(sel) {
		return false
	}
	for _, loc := range callSite.FindAllStringSubmatchIndex(sel, -1) {
		if !guardWords[sel[loc[2]:loc[3]]] || (loc[0] > 0 && (sel[loc[0]-1] == '.' || sel[loc[0]-1] == '"')) {
			return false
		}
	}
	for _, loc := range fromWord.FindAllStringIndex(sel, -1) {
		for _, item := range joinSep.Split(fromClause(sel[loc[1]:]), -1) {
			item = strings.TrimSpace(item)
			if item == "" || strings.HasPrefix(item, "(") {
				continue
			}
			name, _, _ := strings.Cut(item, " ")
			if !catalogRel.MatchString(name) {
				return false
			}
		}
	}
	return true
}

func fromClause(s string) string {
	depth := 0
	for i, r := range s {
		switch r {
		case '(':
			depth++
		case ')':
			depth--
			if depth < 0 {
				return s[:i]
			}
		case ' ':
			if depth == 0 && fromEnd.MatchString(s[i:]) {
				return s[:i]
			}
		}
	}
	return s
}

func isCreateTableAs(code string) bool {
	loc := createTable.FindStringIndex(code)
	if loc == nil {
		return false
	}
	var top strings.Builder
	depth := 0
	for _, r := range code[loc[1]:] {
		switch {
		case r == '(':
			depth++
		case r == ')':
			depth--
		case depth == 0:
			top.WriteRune(r)
		}
	}
	return asClause.MatchString(strings.TrimSpace(top.String()))
}

func guardedWorkOK(s string) bool {
	if isCreateTableAs(s) {
		return false
	}
	if guardedWork.MatchString(s) {
		return true
	}
	if createOK.MatchString(s) {
		return true
	}
	m := alterTable.FindStringSubmatch(s)
	if m == nil {
		return false
	}
	for _, action := range splitTopLevel(m[3]) {
		if !guardedAdd.MatchString(action) {
			return false
		}
	}
	return true
}

func clip(s string) string {
	if len(s) > 48 {
		return s[:48] + "..."
	}
	return s
}

func checkMigrationFiles(ws *Workspace, e *embeddedFS) []Violation {
	var out []Violation
	seen := map[string]bool{}
	var files []string
	for _, p := range e.patterns {
		matches, err := filepath.Glob(filepath.Join(e.dir, strings.TrimPrefix(p, "all:")))
		if err != nil {
			continue
		}
		for _, m := range matches {
			_ = filepath.WalkDir(m, func(path string, d fs.DirEntry, err error) error {
				if err != nil {
					return nil
				}
				if d.IsDir() {
					if path != m && (strings.HasPrefix(d.Name(), ".") || strings.HasPrefix(d.Name(), "_")) {
						return filepath.SkipDir
					}
					return nil
				}
				if strings.HasSuffix(path, ".sql") && !seen[path] {
					seen[path] = true
					files = append(files, path)
				}
				return nil
			})
		}
	}
	for _, path := range files {
		rel := path
		if r, err := filepath.Rel(ws.Root, path); err == nil && !strings.HasPrefix(r, "..") {
			rel = r
		}
		data, err := os.ReadFile(path)
		if err != nil {
			out = append(out, Violation{Guard: G16, Pkg: e.pkg.PkgPath, Pos: rel, Symbols: []string{e.key()}, Msg: "cannot read migration: " + err.Error()})
			continue
		}
		for _, st := range splitSQL(string(data)) {
			if msg := statementProblem(st); msg != "" {
				out = append(out, Violation{Guard: G16, Pkg: e.pkg.PkgPath, Pos: rel + ":" + strconv.Itoa(st.line), Symbols: []string{e.key()}, Msg: msg})
			}
		}
	}
	return out
}
