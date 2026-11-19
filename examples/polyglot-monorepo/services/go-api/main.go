package main

import (
	"fmt"
	"net/http"
)

// Greeting returns the API greeting.
func Greeting(name string) string {
	if name == "" {
		name = "world"
	}
	return fmt.Sprintf("hello, %s", name)
}

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, Greeting(r.URL.Query().Get("name")))
	})
	_ = http.ListenAndServe("127.0.0.1:8080", nil)
}
