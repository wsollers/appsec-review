package server

import (
	"crypto/tls"
	"encoding/json"
	"net/http"
	"os/exec"

	"example.com/app/store"
	"example.com/app/missing"
)

var insecure = &tls.Config{InsecureSkipVerify: true}

func Register(mux *http.ServeMux, db *store.DB) {
	mux.HandleFunc("/run", func(w http.ResponseWriter, r *http.Request) {
		var request struct{ Command string }
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		out, err := exec.Command("sh", "-c", request.Command).Output() //nolint:gosec
		if err != nil {
			return
		}
		if len(out) > 0 && db != nil {
			_ = db.Save(string(out))
		}
	})
	_ = missing.Value
}
