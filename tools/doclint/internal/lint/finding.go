// Package lint implements the documentation guards G26 (burden sentences, symbol references,
// banned links) and G27 (embedded examples) over Markdown files and exported doc comments.
package lint

import "fmt"

// Rule identifies the guard that produced a Finding.
type Rule string

// Guard identifiers reported in Finding.Rule.
const (
	RuleBurden   Rule = "G26a"
	RuleSymbol   Rule = "G26b"
	RuleBanned   Rule = "G26c"
	RuleEmbed    Rule = "G27"
	RuleEnforced Rule = "G26a-enforced-by"
)

// Finding is one guard violation located at File:Line, with File relative to the repository root.
type Finding struct {
	Rule    Rule
	File    string
	Line    int
	Message string
}

// String renders the finding as file:line: [rule] message.
func (f Finding) String() string {
	return fmt.Sprintf("%s:%d: [%s] %s", f.File, f.Line, f.Rule, f.Message)
}
