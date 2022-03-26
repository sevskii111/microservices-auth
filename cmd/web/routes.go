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
	mux.Post("/auth/register", formMiddleware.ThenFunc(app.register))
	mux.Post("/auth/login", formMiddleware.ThenFunc(app.logIn))
	mux.Get("/auth/refresh", rtCookieAsFormMiddleware.ThenFunc(app.refresh))
	mux.Post("/auth/refresh", formMiddleware.ThenFunc(app.refresh))
	mux.Get("/auth/logout", rtCookieAsFormMiddleware.ThenFunc(app.logout))
	mux.Post("/auth/logout", formMiddleware.ThenFunc(app.logout))

	return standardMiddleware.Then(mux)
}
