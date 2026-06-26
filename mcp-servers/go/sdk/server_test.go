package sdk

import "testing"

func TestSanitizeParamsBlocksArgInjection(t *testing.T) {
	cases := []struct {
		name   string
		params map[string]any
		bad    string // expected offending key, "" if should pass
	}{
		{"flag-injection", map[string]any{"target": "--script=evil"}, "target"},
		{"leading-dash-url", map[string]any{"url": "-oN/tmp/x"}, "url"},
		{"whitespace-split", map[string]any{"host": "a.com b.com"}, "host"},
		{"newline-inject", map[string]any{"url": "a.com\n--dump"}, "url"},
		{"legit-url", map[string]any{"url": "https://my-site.com/a?b=1&c=2"}, ""},
		{"legit-target", map[string]any{"target": "scanme.nmap.org", "fast": true}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			k, _ := sanitizeParams(c.params)
			if k != c.bad {
				t.Fatalf("sanitizeParams(%v) offending key = %q, want %q", c.params, k, c.bad)
			}
		})
	}
}
