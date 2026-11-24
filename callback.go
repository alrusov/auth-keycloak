/*
Обратные вызовы
*/
package kc

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/alrusov/auth"
	"github.com/alrusov/log"
)

//----------------------------------------------------------------------------------------------------------------------------//

// Обработчк обратных HTTP вызовов
func (ah *AuthHandler) Handler(id uint64, prefix string, path string, w http.ResponseWriter, r *http.Request) (processed bool) {

	switch path {

	case ah.logoutRedirectPath: // logout
		processed = true
		requestQuery := r.URL.Query()

		// Удаляем KC куки, добавлем токен и летим на закрытие сессии
		baseURL := ah.baseURL(r)
		ah.setCookie(w, baseURL, accessTokenName, "", -1)
		ah.setCookie(w, baseURL, refreshTokenName, "", -1)
		w.Header().Set("Location", fmt.Sprintf("%s?redirect_uri=%s", ah.clientCfg.EndSessionEndpoint, url.QueryEscape(requestQuery.Get("referer"))))
		w.WriteHeader(http.StatusFound)

		return

	case ah.callbackRedirectPath: // callback от KC сервера
		processed = true
		requestQuery := r.URL.Query()

		errorMsg := requestQuery.Get("error")
		if errorMsg != "" {
			// Пришла ошибка
			ah.errorReply(id, w, r, http.StatusBadRequest, "%s (%s)", errorMsg, requestQuery.Get("error_description"))
			return
		}

		// Проброшенный из первичного вызова state
		state := requestQuery.Get("state")

		// state = одноразовое значение из куки + адрес возврата
		stateCookie, err := r.Cookie(stateCookieName)
		if err != nil || len(stateCookie.Value) != stateNonceLen || !strings.HasPrefix(state, stateCookie.Value) {
			ah.errorReply(id, w, r, http.StatusBadRequest, "State did not match")
			return
		}

		baseURL := ah.baseURL(r)
		ah.setCookie(w, baseURL, stateCookieName, "", -1)

		referer, err := url.QueryUnescape(state[stateNonceLen:])
		if err != nil {
			// Куда потом лететь не сказали
			ah.errorReply(id, w, r, http.StatusInternalServerError, "Bad referer (%s)", err)
			return
		}

		// Обмениваем временный токен на постоянный
		oa := ah.oaConfig(baseURL, r)
		oauth2Token, err := oa.Exchange(context.Background(), requestQuery.Get("code"))
		if err != nil {
			ah.errorReply(id, w, r, http.StatusInternalServerError, "Failed to exchange token (%s)", err)
			return
		}

		// Получаем ID токен
		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			ah.errorReply(id, w, r, http.StatusInternalServerError, "No id_token field in oauth2 token")
			return
		}

		// Проверяем ID токен
		_, err = ah.verifier.Verify(context.Background(), rawIDToken)
		if err != nil {
			ah.errorReply(id, w, r, http.StatusInternalServerError, "Illegal id_token")
			return
		}

		// Получаем access токен
		accessToken, ok := oauth2Token.Extra("access_token").(string)
		if !ok {
			ah.errorReply(id, w, r, http.StatusInternalServerError, "No access_token field in oauth2 token")
			return
		}

		// Получаем refresh токен
		refreshToken, ok := oauth2Token.Extra("refresh_token").(string)
		if !ok {
			ah.errorReply(id, w, r, http.StatusInternalServerError, "No refresh_token field in oauth2 token")
			return
		}

		// Всё получилось, устанавливаем заголовки с токенами и летим, куда попросили

		auth.Log.Message(log.DEBUG, "[%d] The new token acquired", id)

		ah.setCookie(w, baseURL, accessTokenName, accessToken, 0)
		ah.setCookie(w, baseURL, refreshTokenName, refreshToken, 0)
		w.Header().Set("Location", safeReferer(referer, baseURL))
		w.WriteHeader(http.StatusFound)

		return
	}

	return
}

//----------------------------------------------------------------------------------------------------------------------------//
