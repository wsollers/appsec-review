package spans

import "strings"

var limit = 4 // ANCHOR:none

type Store struct {
	items []string
}

func (s *Store) Add(item string) int { // BEGIN:Add
	s.items = append(s.items, strings.TrimSpace(item)) // ANCHOR:Add
	go func() {
		s.items = append(s.items, "{") // ANCHOR:Add
	}()
	return len(s.items)
} // END:Add

func Join(parts []string) string { // BEGIN:Join
	clean := func(value string) string { // BEGIN:clean
		return strings.TrimSpace(value) // ANCHOR:clean
	} // END:clean
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		out = append(out, clean(part)) // ANCHOR:Join
	}
	return strings.Join(out, `,}`)
} // END:Join
