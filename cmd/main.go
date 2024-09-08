package main

import "net/http"

func main() {
	http.HandleFunc("/v1/auth", handleAuth)

	http.ListenAndServe(":5555", nil)
}
