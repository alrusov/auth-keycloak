/*
Cookies, state и проверка адреса возврата
*/
package kc

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

//----------------------------------------------------------------------------------------------------------------------------//

const (
	stateCookieName   = "KCST" // Имя куки с одноразовым значением state
	stateNonceLen     = 32     // Длина значения в hex
	stateCookieMaxAge = 600    // Сколько секунд ждём возврата с сервера kc
)

//----------------------------------------------------------------------------------------------------------------------------//

// Установка куки. HttpOnly - токены не должны быть доступны скриптам страницы (кража через XSS),
// SameSite=Lax - не уходят с межсайтовыми POST, но приходят при возврате с kc (переход верхнего уровня),
// Secure - если нас открыли по https. maxAge < 0 - удалить куку.
func (ah *AuthHandler) setCookie(w http.ResponseWriter, baseURL string, name string, value string, maxAge int) {
	s := fmt.Sprintf("%s=%s; path=/; domain=%s; HttpOnly; SameSite=Lax", name, value, ah.options.Domain)

	if strings.HasPrefix(strings.ToLower(baseURL), "https:") {
		s += "; Secure"
	}

	switch {
	case maxAge < 0:
		s += "; Max-Age=0; expires=Thu, 1 Jan 1970 00:00:00 UTC"
	case maxAge > 0:
		s += fmt.Sprintf("; Max-Age=%d", maxAge)
	}

	w.Header().Add("Set-Cookie", s)
}

//----------------------------------------------------------------------------------------------------------------------------//

// Одноразовое значение для state. Раньше префиксом state был uuid процесса - одинаковый для всех и виден
// в любом 302 на kc, так что state не защищал от подстановки чужого входа (login CSRF)
func newStateNonce() (string, error) {
	b := make([]byte, stateNonceLen/2)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

//----------------------------------------------------------------------------------------------------------------------------//

// Адрес возврата после входа: только наш собственный (тот же scheme://host[:port], что и baseURL)
// или относительный путь. Иначе - корень, чтобы callback не был открытым редиректом.
func safeReferer(referer string, baseURL string) string {
	if referer == "" {
		return "/"
	}

	u, err := url.Parse(referer)
	if err != nil {
		return "/"
	}

	if u.Scheme == "" && u.Host == "" {
		// Относительный: "/path", но не "//host" и не "\\host"
		if strings.HasPrefix(referer, "/") && !strings.HasPrefix(referer, "//") && !strings.HasPrefix(referer, `/\`) {
			return referer
		}
		return "/"
	}

	b, err := url.Parse(baseURL)
	if err != nil {
		return "/"
	}

	if strings.EqualFold(u.Scheme, b.Scheme) && strings.EqualFold(u.Host, b.Host) && u.User == nil {
		return referer
	}

	return "/"
}

//----------------------------------------------------------------------------------------------------------------------------//
