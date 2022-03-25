package main

import (
	"net/http"

	"github.com/bmizerany/pat"
	"github.com/justinas/alice"
)

func (app *application) routes() http.Handler {
	standardMiddleware := alice.New(app.recoverPanic, app.logRequest, secureHeaders)
	formMiddleware := alice.New(app.parseForm)
	rtCookieAsFormMiddleware := alice.New(refreshTokenCookieAsForm)

	mux := pat.New()
	mux.Post("/register", formMiddleware.ThenFunc(app.register))
	mux.Post("/auth", formMiddleware.ThenFunc(app.auth))
	mux.Get("/refresh", rtCookieAsFormMiddleware.ThenFunc(app.refresh))
	mux.Post("/refresh", formMiddleware.ThenFunc(app.refresh))
	mux.Get("/logout", rtCookieAsFormMiddleware.ThenFunc(app.logout))
	mux.Post("/logout", formMiddleware.ThenFunc(app.logout))

	return standardMiddleware.Then(mux)
}
