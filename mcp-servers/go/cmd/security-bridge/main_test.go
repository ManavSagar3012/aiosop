package main

import "testing"

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
