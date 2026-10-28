package main

import (
	"database/sql"
	"encoding/gob"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
)

type Handler interface {
	Handle(input string) string
}

type Upper struct{}

func (Upper) Handle(input string) string { return strings.ToUpper(input) }

type Lower struct{}

func (Lower) Handle(input string) string { return strings.ToLower(input) }

func dispatch(h Handler, input string) string {
	return h.Handle(input)
}

// Apply is exported and never called, so fn has no resolvable target.
func Apply(fn func(string) string, s string) string {
	return fn(s)
}

func quote(name string) string {
	return "'" + name + "'"
}

func lookup(db *sql.DB, name string) {
	db.Exec("SELECT id FROM users WHERE name = " + quote(name))
}

func serve(w http.ResponseWriter, r *http.Request) {
	db, _ := sql.Open("sqlite", "app.db")
	name := r.FormValue("name")
	lookup(db, name)
	exec.Command(name).Run()
	f, _ := os.Open(filepath.Clean(name))
	f.Close()
	http.Get(name)
	gob.NewDecoder(r.Body).Decode(&name)
	count, _ := strconv.Atoi(r.FormValue("n"))
	if count < 100 {
		strings.Repeat("x", count)
	}
	strings.Repeat("y", int(int32(count)))
	var v map[string]string
	json.Unmarshal([]byte(name), &v)
	dispatch(Upper{}, name)
	dispatch(Lower{}, name)
	pick := quote
	pick(name)
	reflect.ValueOf(quote).Call(nil)
}

func main() {
	cmd := exec.Command(os.Args[1] + os.Getenv("SUFFIX"))
	cmd.Run()
	http.HandleFunc("/", serve)
	http.ListenAndServe(":8080", nil)
}
