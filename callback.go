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
		w.Header().Add("Set-Cookie", fmt.Sprintf("%s=%s; path=/; domain=%s; expires=Thu, 1 Jan 1970 00:00:00 UTC;", accessTokenName, "", ah.options.Domain))
		w.Header().Add("Set-Cookie", fmt.Sprintf("%s=%s; path=/; domain=%s; expires=Thu, 1 Jan 1970 00:00:00 UTC;", refreshTokenName, "", ah.options.Domain))
		w.Header().Set("Authorization", "Bearer "+requestQuery.Get("token"))
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

		if !strings.HasPrefix(state, ah.uuid) {
			// Нет uuid в начале - что-то не то прислали
			ah.errorReply(id, w, r, http.StatusBadRequest, "State did not match")
			return
		}

		referer, err := url.QueryUnescape(state[len(ah.uuid):])
		if err != nil {
			// Куда потом лететь не сказали
			ah.errorReply(id, w, r, http.StatusInternalServerError, "Bad referer (%s)", err)
			return
		}

		// Обмениваем временный токен на постоянный
		oa := ah.oaConfig(ah.baseURL(r), r)
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

		auth.Log.Message(log.DEBUG, "The new token acquired: %s", accessToken)

		w.Header().Add("Set-Cookie", fmt.Sprintf("%s=%s; path=/; domain=%s;", accessTokenName, accessToken, ah.options.Domain))
		w.Header().Add("Set-Cookie", fmt.Sprintf("%s=%s; path=/; domain=%s;", refreshTokenName, refreshToken, ah.options.Domain))
		w.Header().Set("Location", referer)
		w.WriteHeader(http.StatusFound)

		return
	}

	return
}

//----------------------------------------------------------------------------------------------------------------------------//
