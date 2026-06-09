package sdk

import (
	"encoding/json"
	"log"
	"net/http"
	"time"
)

type Tool struct {
	Name             string                   `json:"name"`
	Description      string                   `json:"description"`
	Parameters       []map[string]any         `json:"parameters"`
	Returns          map[string]any           `json:"returns"`
	TimeoutSeconds   int                      `json:"timeout_seconds"`
	RequiresApproval bool                     `json:"requires_approval"`
	ScopeCheck        bool                     `json:"scope_check"`
	Handler           func(map[string]any) any `json:"-"`
}

type Server struct {
	ID        string
	Version   string
	Tools     map[string]Tool
	StartedAt time.Time
}

func NewServer(id string) *Server {
	return &Server{ID: id, Version: "0.1.0", Tools: map[string]Tool{}, StartedAt: time.Now()}
}

func (s *Server) Register(tool Tool) {
	s.Tools[tool.Name] = tool
}

func (s *Server) Run(addr string) error {
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"status": "ready", "server_id": s.ID})
	})
	http.HandleFunc("/mcp/initialize", func(w http.ResponseWriter, r *http.Request) {
		tools := make([]Tool, 0, len(s.Tools))
		for _, tool := range s.Tools {
			tools = append(tools, tool)
		}
		writeJSON(w, map[string]any{
			"server_id":    s.ID,
			"version":      s.Version,
			"capabilities": []string{"tools"},
			"tools":        tools,
			"status":       "ready",
		})
	})
	http.HandleFunc("/mcp/execute", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ToolName   string         `json:"tool_name"`
			Parameters map[string]any `json:"parameters"`
			RequestID  string         `json:"request_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		tool, ok := s.Tools[req.ToolName]
		if !ok {
			writeJSON(w, map[string]any{"request_id": req.RequestID, "status": "error", "error": "unknown tool"})
			return
		}
		writeJSON(w, map[string]any{"request_id": req.RequestID, "status": "success", "result": tool.Handler(req.Parameters)})
	})
	log.Printf("%s listening on %s", s.ID, addr)
	return http.ListenAndServe(addr, nil)
}

func writeJSON(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(data)
}
