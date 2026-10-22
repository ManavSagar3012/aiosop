package sdk

// Validate the actual Python MCPInitializeRequest transport contract before
// responding with an inert catalog. Initialization metadata is NEVER
// authorization: valid scope/credentials alone enable no scanner.
import (
	"bytes"
	"encoding/json"
	"errors"
	"regexp"
)

var nativeInitSessionRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

func validNativeInitialize(raw []byte) error {
	patterns := []map[string]bool{
		{"scope": true, "auth_credentials": true, "session_id": true, "metadata": true},
		{"scope": true, "auth_credentials": true, "session_id": true},
		{"scope": true, "credentials": true, "session_id": true, "metadata": true},
		{"scope": true, "credentials": true, "session_id": true},
		{"scope": true, "session_id": true, "metadata": true},
		{"scope": true, "session_id": true},
	}
	var fields map[string]json.RawMessage
	for _, expected := range patterns {
		parsed, err := decodeExactObject(raw, expected)
		if err == nil {
			fields = parsed
			break
		}
	}
	if fields == nil {
		return errors.New("MCP initialization has ambiguous or missing fields")
	}
	var session string
	if json.Unmarshal(fields["session_id"], &session) != nil || !nativeInitSessionRE.MatchString(session) {
		return errors.New("MCP session identity malformed")
	}
	for _, field := range []string{"scope", "auth_credentials", "credentials", "metadata"} {
		value, exists := fields[field]
		if !exists {
			continue
		}
		clean := bytes.TrimSpace(value)
		if len(clean) < 2 || clean[0] != '{' || clean[len(clean)-1] != '}' {
			return errors.New("MCP scope/credentials must be JSON objects")
		}
		var object map[string]json.RawMessage
		if err := json.Unmarshal(clean, &object); err != nil || object == nil {
			return errors.New("Invalid MCP initialization metadata")
		}
	}
	return nil
}
