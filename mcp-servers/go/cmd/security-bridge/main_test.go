package main

import (
	"strings"
	"testing"
)

func hasArg(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}

// buildSqlmapArgs must always add --ignore-code (default 401,403) so sqlmap does
// not abort on auth-gated endpoints (the JS-001 login-SQLi false negative).
func TestBuildSqlmapArgsDefaultsIgnoreCode(t *testing.T) {
	args := buildSqlmapArgs(map[string]any{
		"url":  "http://localhost:3000/rest/user/login",
		"data": `{"email":"a*","password":"b"}`,
	})
	if !hasArg(args, "--ignore-code=401,403") {
		t.Fatalf("expected default --ignore-code=401,403, got %v", args)
	}
	if !hasArg(args, `--data={"email":"a*","password":"b"}`) {
		t.Fatalf("data flag missing/altered, got %v", args)
	}
}

func TestBuildSqlmapArgsIgnoreCodeOverrideSanitised(t *testing.T) {
	// valid override is honoured
	args := buildSqlmapArgs(map[string]any{"url": "http://x", "ignore_code": "500"})
	if !hasArg(args, "--ignore-code=500") {
		t.Fatalf("valid override not applied, got %v", args)
	}
	// a malicious override (spaces/extra tokens) is rejected -> falls back to default
	bad := buildSqlmapArgs(map[string]any{"url": "http://x", "ignore_code": "401 --dump ;rm"})
	if !hasArg(bad, "--ignore-code=401,403") {
		t.Fatalf("malicious override must fall back to default, got %v", bad)
	}
	for _, a := range bad {
		if strings.Contains(a, "rm") || strings.Contains(a, ";") {
			t.Fatalf("sanitiser leaked tokens into argv: %v", bad)
		}
	}
}

func TestIsCodeList(t *testing.T) {
	for _, ok := range []string{"401", "401,403", "500,502,401"} {
		if !isCodeList(ok) {
			t.Errorf("expected %q to be a valid code list", ok)
		}
	}
	for _, bad := range []string{"", "401 403", "401;rm", "abc", "401,--dump"} {
		if isCodeList(bad) {
			t.Errorf("expected %q to be rejected", bad)
		}
	}
}

// A realistic sqlmap stdout for a confirmed injection (trimmed but structurally faithful).
const sqlmapInjectable = `
[02:26:30] [INFO] testing connection to the target URL
[02:26:31] [INFO] GET parameter 'id' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable
[02:26:32] [INFO] GET parameter 'id' is 'MySQL >= 5.0 AND error-based' injectable
sqlmap identified the following injection point(s) with a total of 84 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 1234=1234

    Type: error-based
    Title: MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: id=1 AND (SELECT 1234 FROM(SELECT COUNT(*),CONCAT(0x71,0x71))x)
---
[02:26:35] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0
`

const sqlmapClean = `
[02:10:01] [INFO] testing connection to the target URL
[02:10:05] [INFO] testing if GET parameter 'q' is dynamic
[02:10:09] [WARNING] GET parameter 'q' does not appear to be dynamic
[02:10:30] [CRITICAL] all tested parameters do not appear to be injectable.
`

func TestParseSqlmapOutput_Injectable(t *testing.T) {
	d := parseSqlmapOutput(sqlmapInjectable)
	if injectable, _ := d["injectable"].(bool); !injectable {
		t.Fatalf("expected injectable=true, got %v", d["injectable"])
	}
	if d["parameter"] != "id (GET)" {
		t.Errorf("expected parameter 'id (GET)', got %q", d["parameter"])
	}
	if dbms, _ := d["dbms"].(string); dbms != "MySQL >= 5.0" {
		t.Errorf("expected dbms 'MySQL >= 5.0', got %q", dbms)
	}
	techniques, _ := d["techniques"].([]string)
	if len(techniques) != 2 {
		t.Errorf("expected 2 techniques, got %d: %v", len(techniques), techniques)
	}
	payloads, _ := d["payloads"].([]string)
	if len(payloads) != 2 {
		t.Errorf("expected 2 payloads, got %d: %v", len(payloads), payloads)
	}
}

func TestParseSqlmapOutput_Clean(t *testing.T) {
	d := parseSqlmapOutput(sqlmapClean)
	if injectable, _ := d["injectable"].(bool); injectable {
		t.Fatalf("expected injectable=false for clean output, got true")
	}
	payloads, _ := d["payloads"].([]string)
	if len(payloads) != 0 {
		t.Errorf("expected 0 payloads, got %d", len(payloads))
	}
}

// A 500 / reflected DB error must NOT be read as a confirmed injection.
func TestParseSqlmapOutput_ErrorNotInjection(t *testing.T) {
	raw := "[02:26:31] [WARNING] the web server responded with an HTTP error code (500)\n" +
		"[02:26:34] [CRITICAL] all tested parameters do not appear to be injectable."
	d := parseSqlmapOutput(raw)
	if injectable, _ := d["injectable"].(bool); injectable {
		t.Fatalf("HTTP 500 alone must not count as injectable")
	}
}

func TestClampInt(t *testing.T) {
	cases := []struct{ v, lo, hi, want int }{
		{0, 1, 5, 1},
		{3, 1, 5, 3},
		{9, 1, 5, 5},
		{2, 1, 3, 2},
		{7, 1, 3, 3},
	}
	for _, c := range cases {
		if got := clampInt(c.v, c.lo, c.hi); got != c.want {
			t.Errorf("clampInt(%d,%d,%d)=%d want %d", c.v, c.lo, c.hi, got, c.want)
		}
	}
}
