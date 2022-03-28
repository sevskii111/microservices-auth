package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/sevskii111/microservices-auth/pkg/forms"
	"github.com/sevskii111/microservices-auth/pkg/models"
)

type JSONRes struct {
	Errors  forms.FormErrors
	Success bool
}

type AuthRes struct {
	Success      bool
	AccessToken  string
	RefreshToken string
}

func (app *application) json(w http.ResponseWriter, res interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	jsonResp, err := json.Marshal(res)
	if err != nil {
		app.serverError(w, err)
	}
	w.Write(jsonResp)
}

func (app *application) formResult(w http.ResponseWriter, form *forms.Form) {
	res := JSONRes{
		Errors:  form.Errors,
		Success: form.Valid(),
	}
	app.json(w, res)
}

func (app *application) authUser(w http.ResponseWriter, user *models.User) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"UserID":    user.ID,
		"Username":  user.Username,
		"IsAdmin":   user.IsAdmin,
		"ExpiresAt": time.Now().Add(time.Minute * time.Duration(app.cfg.TokenLifetime)).Unix(),
	})
	accessToken, err := token.SignedString([]byte(app.cfg.Secret))
	if err != nil {
		app.serverError(w, err)
		return
	}

	refreshToken, err := app.refreshTokens.Create(user.ID)
	if err != nil {
		app.serverError(w, err)
		return
	}
	w.Header().Set("Set-Cookie", fmt.Sprintf("refreshToken=%s; HttpOnly", refreshToken.String()))
	res := AuthRes{
		AccessToken:  accessToken,
		RefreshToken: refreshToken.String(),
		Success:      true,
	}
	app.json(w, res)
}

func (app *application) serverError(w http.ResponseWriter, err error) {
	trace := fmt.Sprintf("%s\n%s", err.Error(), debug.Stack())
	app.errorLog.Output(2, trace)

	http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
}

func (app *application) clientError(w http.ResponseWriter, status int) {
	http.Error(w, http.StatusText(status), status)
}

func (app *application) notFound(w http.ResponseWriter) {
	app.clientError(w, http.StatusNotFound)
}
