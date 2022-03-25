package main

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/sevskii111/microservices-auth/pkg/forms"
	"github.com/sevskii111/microservices-auth/pkg/models"
)

func (app *application) register(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		app.clientError(w, http.StatusBadRequest)
		return
	}

	form := forms.New(r.PostForm)
	form.Required("username", "password")
	form.MaxLength("username", 255)
	form.MaxLength("password", 32)
	form.MinLength("password", 8)

	if form.Valid() {
		err = app.users.Insert(form.Get("username"), form.Get("password"))
		if err != nil {
			if errors.Is(err, models.ErrDuplicateUsername) {
				form.Errors.Add("username", "Username is taken")
				app.formResult(w, form)
			} else {
				app.serverError(w, err)
			}
			return
		}
	}

	app.formResult(w, form)
}

func (app *application) auth(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		app.clientError(w, http.StatusBadRequest)
		return
	}

	form := forms.New(r.PostForm)
	form.Required("username", "password")

	if !form.Valid() {
		app.formResult(w, form)
		return
	}

	userID, err := app.users.Authenticate(form.Get("username"), form.Get("password"))
	if err != nil {
		if errors.Is(err, models.ErrInvalidCredentials) {
			form.Errors.Add("generic", "Username or Password is incorrect")
			app.formResult(w, form)
		} else {
			app.serverError(w, err)
		}
		return
	}
	user, err := app.users.Get(userID)
	if err != nil {
		app.serverError(w, err)
		return
	}
	app.authUser(w, user)
}

func (app *application) refresh(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		refreshToken := ""
		refreshTokenCookie, err := r.Cookie("refreshToken")
		if err == nil {
			refreshToken = refreshTokenCookie.Value
		}
		r.PostForm = url.Values{
			"refreshToken": []string{refreshToken},
		}
	} else {
		err := r.ParseForm()
		if err != nil {
			app.clientError(w, http.StatusBadRequest)
			return
		}
	}

	form := forms.New(r.PostForm)
	form.Required("refreshToken")

	if !form.Valid() {
		app.formResult(w, form)
		return
	}

	userID, err := app.refreshTokens.GetUserId(form.Get("refreshToken"))
	if err != nil {
		if errors.Is(err, models.ErrInvalidToken) {
			form.Errors.Add("refreshToken", "Refresh token is incorrect")
			app.formResult(w, form)
		} else {
			app.serverError(w, err)
		}
		return
	}

	user, err := app.users.Get(userID)
	if err != nil {
		app.serverError(w, err)
		return
	}

	app.authUser(w, user)
}
