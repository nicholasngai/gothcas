package main

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/pelicaned/gothcas"
)

func initialize() {
	casProvider, err := gothcas.New("https://casserver.herokuapp.com/", "http://localhost:8080/auth/callback", &gothcas.AttributeMap{
		Email:     "email",
		FirstName: "first-name",
		LastName:  "last-name",
		UserID:    "uid",
	})
	if err != nil {
		log.Fatal(err)
	}
	goth.UseProviders(casProvider)
}

func main() {
	initialize()

	mux := http.DefaultServeMux
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(context.WithValue(r.Context(), "provider", "cas"))
		gothic.BeginAuthHandler(w, r)
	})
	mux.HandleFunc("/auth/callback", func(w http.ResponseWriter, r *http.Request) {
		user, err := gothic.CompleteUserAuth(w, r)
		if err != nil {
			log.Print(err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		fmt.Fprintln(w, user)
	})

	http.ListenAndServe("localhost:8080", nil)
}
