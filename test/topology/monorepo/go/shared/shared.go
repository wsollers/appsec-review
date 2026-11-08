// Package shared holds helpers used by the service module.
package shared

// Greeting returns a fixed message for name.
func Greeting(name string) string {
	return "hello, " + name
}
