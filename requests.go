/*
Взаимодействие с KC сервером
*/
package kc

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/url"
	"time"

	"github.com/alrusov/jsonw"
	"github.com/alrusov/misc"
	"github.com/alrusov/stdhttp"
)

//----------------------------------------------------------------------------------------------------------------------------//

// Запрос к серверу
// В result должна быть ссылка на объект того типа, который мы ждем от этого конкретного запроса!
func (ah *AuthHandler) request(result any, method string, uri string, headers misc.StringMap, body []byte) (err error) {
	opts := misc.StringMap{
		stdhttp.RequestOptionSkipTLSVerification: fmt.Sprint(ah.options.SkipTLSVerification),
		stdhttp.RequestOptionGzip:                fmt.Sprint(ah.options.WithGzip),
	}

	buf, _, err := stdhttp.Request(method, uri, time.Duration(ah.options.Timeout), opts, headers, body)
	if err != nil {
		b := []byte{}
		if buf != nil {
			b = buf.Bytes()
		}
		err = fmt.Errorf("%s (%s)", err, b)
		return
	}

	err = jsonw.Unmarshal(buf.Bytes(), result)
	if err != nil {
		return
	}

	return
}

//----------------------------------------------------------------------------------------------------------------------------//

// Загрузка конфигурации
func (ah *AuthHandler) loadClientConfig() (err error) {
	data := new(kcClientConfig)
	uri := fmt.Sprintf("%s/auth/realms/%s/.well-known/openid-configuration", ah.options.AuthServer, ah.options.ClientRealm)

	err = ah.request(&data, stdhttp.MethodGET, uri, nil, nil)
	if err != nil {
		return
	}

	ah.clientCfg = data
	return
}

//----------------------------------------------------------------------------------------------------------------------------//

// Загузка и проверка публичного ключа
func (ah *AuthHandler) loadPubKey() (tryAgain bool, err error) {
	data := new(kcIssuer)
	uri := ah.clientCfg.Issuer

	err = ah.request(&data, stdhttp.MethodGET, uri, nil, nil)
	if err != nil {
		// Не получилось соединиться, будем пробовать еще
		tryAgain = true
		return
	}

	// Если ниже возникнут ошибки, то это не лечится и повторять попытки смысла нет
	tryAgain = false

	block, _ := pem.Decode([]byte(fmt.Sprintf("\n-----BEGIN KEY-----\n%s\n-----END KEY-----", data.PublicKey)))
	if block == nil {
		err = fmt.Errorf("illegal KC public key")
		return
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return
	}

	pubKey, ok := pub.(*rsa.PublicKey)
	if !ok {
		err = fmt.Errorf("KC public key is not RSA")
		return
	}

	ah.kcPubKey = pubKey
	return
}

//----------------------------------------------------------------------------------------------------------------------------//

// Обновить токен
func (ah *AuthHandler) refreshToken(refreshToken string) (newAccessToken string, newRefreshToken string, err error) {
	data := new(kcToken)
	uri := ah.clientCfg.TokenEndpoint

	headers := misc.StringMap{
		"Content-Type": "application/x-www-form-urlencoded",
	}

	body := []byte(
		fmt.Sprintf(
			"client_id=%s&client_secret=%s&grant_type=refresh_token&refresh_token=%s",
			url.QueryEscape(ah.options.ClientID),
			url.QueryEscape(ah.options.ClientSecret),
			url.QueryEscape(refreshToken),
		),
	)

	err = ah.request(&data, stdhttp.MethodPOST, uri, headers, body)
	if err != nil {
		return
	}

	newAccessToken = data.AccessToken
	newRefreshToken = data.RefreshToken
	return
}

//----------------------------------------------------------------------------------------------------------------------------//

// Получить информацию о пользователе по его токену
func (ah *AuthHandler) userInfo(accessToken string) (userInfo *kcUserInfo, err error) {
	data := new(kcUserInfo)
	uri := ah.clientCfg.UserinfoEndpoint

	headers := misc.StringMap{
		"Content-Type": "application/x-www-form-urlencoded",
	}

	body := []byte(
		fmt.Sprintf(
			"access_token=%s",
			url.QueryEscape(accessToken),
		),
	)

	err = ah.request(&data, stdhttp.MethodPOST, uri, headers, body)
	if err != nil {
		return
	}

	userInfo = data
	return
}

//----------------------------------------------------------------------------------------------------------------------------//
