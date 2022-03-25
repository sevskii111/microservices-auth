package main

import (
	"net/http"

	"github.com/bmizerany/pat"
	"github.com/justinas/alice"
)

func (app *application) routes() http.Handler {
	standardMiddleware := alice.New(app.recoverPanic, app.logRequest, secureHeaders)

	mux := pat.New()
	mux.Post("/register", standardMiddleware.ThenFunc(app.register))
	mux.Post("/auth", standardMiddleware.ThenFunc(app.auth))
	mux.Get("/refresh", standardMiddleware.ThenFunc(app.refresh))
	mux.Post("/refresh", standardMiddleware.ThenFunc(app.refresh))

	return mux
}
