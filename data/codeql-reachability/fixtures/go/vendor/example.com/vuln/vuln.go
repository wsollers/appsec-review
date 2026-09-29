// Package vuln stands in for a vendored dependency with an advisory on Parse (smoke fixture).
package vuln

func Parse(s string) string { return s }

func Tokenize(s string) []string { return []string{s} }
