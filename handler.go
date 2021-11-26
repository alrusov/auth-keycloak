/*
Основной функционал
*/
package kc

import (
	"crypto/rsa"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/dgrijalva/jwt-go"
	"golang.org/x/oauth2"

	"github.com/alrusov/auth"
	"github.com/alrusov/config"
	"github.com/alrusov/log"
	"github.com/alrusov/misc"
	"github.com/alrusov/stdhttp"
)

//----------------------------------------------------------------------------------------------------------------------------//

type (
	// Описание
	AuthHandler struct {
		initialized bool // Инициализирован?

		http *stdhttp.HTTP // Базовый HTTP

		cfg     *config.AuthMethod // Стандартная конфигурация этого метода
		options *methodOptions     // Дополнительные параметры конфигурации

		uuid string // uuid, генерится при запуске и используется в качестве префикса статура при взаимодействии с kc сервером

		callbackRedirectPath string // Путь до callback
		logoutRedirectPath   string // Путь до logout

		clientCfg *kcClientConfig // Конфигурпция kc клиента
		kcPubKey  *rsa.PublicKey  // Публичный ключ kc

		oauth2ConfigPattern oauth2.Config         // Шаблон конфига соединения с kc
		provider            *oidc.Provider        // oauth2 провайдер
		verifier            *oidc.IDTokenVerifier // oauth2 верифаер токена

		sessionsMutex *sync.RWMutex           // mutex кэша сессий
		sessions      map[string]*sessionData // кэш сессий
	}

	// Дополнительные параметры конфигурации
	methodOptions struct {
		Domain              string        `toml:"domain"`                // Имя домена для установки cookie, должен совпадать с доменом "me", в крайнем случае можно указать IP
		AuthServer          string        `toml:"auth-server"`           //URL kc сервера
		WithGzip            bool          `toml:"gzip"`                  // Использовать gzip при взаимодействии с kc сервером
		TimeoutS            string        `toml:"timeout"`               // Строчное представление таймаута
		Timeout             time.Duration `toml:"-"`                     // Таймаут
		SkipTLSVerification bool          `toml:"skip-tls-verification"` // Надо ли проверять TLS сертификат сервера на валидность
		ClientRealm         string        `toml:"client-realm"`          // realm клиента в keycloak
		ClientID            string        `toml:"client-id"`             // ID клиента в keycloak
		ClientSecret        string        `toml:"client-secret"`         // secret клиента в keycloak
		CheckACR            bool          `toml:"check-acr"`             // Дополнительная проверка поля acr токена, при доступе к приложениям по IP рекомендуется отключить
	}

	// Описание сессии
	sessionData struct {
		validBefore  int64         // Время окончания (unixtime)
		RefreshToken string        // Refresh токен
		TokenInfo    jwt.MapClaims `json:"tokenInfo"` // Claims из токена
		UserInfo     *kcUserInfo   `json:"userInfo"`  // Информация о пользователе от kc сервера
	}

	// Конфигурация клиента kc сервера
	kcClientConfig struct {
		Issuer                string `json:"issuer"`                 // Базовый URL, ключ там
		AuthorizationEndpoint string `json:"authorization_endpoint"` // [не используем]
		TokenEndpoint         string `json:"token_endpoint"`         // URL управления токеном, обновляем через него
		IntrospectionEndpoint string `json:"introspection_endpoint"` // [не используем]
		UserinfoEndpoint      string `json:"userinfo_endpoint"`      // URL получения информации о пользователе
		EndSessionEndpoint    string `json:"end_session_endpoint"`   // URL закрытия сессии
		JwksURI               string `json:"jwks_uri"`               // [не используем]
		CheckSessionIframe    string `json:"check_session_iframe"`   // [не используем]
	}

	// Структура для запроса публичного ключа
	kcIssuer struct {
		PublicKey string `json:"public_key"` // Публичный ключ
	}

	// Токен
	kcToken struct {
		AccessToken  string `json:"access_token"`  // Access token
		RefreshToken string `json:"refresh_token"` // Refresh token
	}

	// Информация о пользователе, зависит от настроек kc сервера
	kcUserInfo struct {
		ID         string   `json:"sub"`         // Уникальный ID
		UserName   string   `json:"username"`    // Имя пользователе
		Name       string   `json:"name"`        // Отображаемое имя
		FirstName  string   `json:"given_name"`  // Имя
		LastName   string   `json:"family_name"` // Фамилия
		Initials   string   `json:"initials"`    // Инициалы
		Email      string   `json:"email"`       // email
		Phone      string   `json:"phone"`       // Телефон
		City       string   `json:"city"`        // Город
		Department string   `json:"department"`  // Подразделения
		Groups     []string `json:"groups"`      // Группы, в которых состоит
	}
)

const (
	module = "kc"
	method = "kc"

	accessTokenName  = "KCAT" // Имя куки с access token
	refreshTokenName = "KCRT" // Имя куки с refresh token
)

//----------------------------------------------------------------------------------------------------------------------------//

// Автоматическая инициализация при запуске приложения
func init() {
	Register()
}

// Регистрация метода
func Register() {
	config.AddAuthMethod(module, &methodOptions{}, checkConfig)
}

// Проверка валидности конфига метода
func checkConfig(m *config.AuthMethod) (err error) {
	msgs := misc.NewMessages()

	options, ok := m.Options.(*methodOptions)
	if !ok {
		msgs.Add(`%s.checkConfig: Options is "%T", expected "%T"`, method, m.Options, options)
	}

	options.AuthServer = misc.NormalizeSlashes(options.AuthServer)

	if options.AuthServer == "" {
		msgs.Add(`%s.checkConfig: "auth-server" is not defined"`, method)
	}

	if options.Domain == "" {
		msgs.Add(`%s.checkConfig: "domain" is not defined"`, method)
	}

	if isLocal(options.Domain) {
		msgs.Add(`%s.checkConfig: "domain" cannot be local"`, method)
	}

	if net.ParseIP(options.Domain) == nil {
		options.Domain = "." + options.Domain
	}

	options.Timeout, err = misc.Interval2Duration(options.TimeoutS)
	if err != nil {
		msgs.Add(`%s.checkConfig: "timeout" - %s`, method, err)
	}

	if options.Timeout <= 0 {
		options.Timeout = config.ListenerDefaultTimeout
	}

	if options.ClientRealm == "" {
		msgs.Add(`%s.checkConfig: "client-realm" is not defined"`, method)
	}

	if options.ClientID == "" {
		msgs.Add(`%s.checkConfig: "client-id" is not defined"`, method)
	}

	if options.ClientSecret == "" {
		msgs.Add(`%s.checkConfig: "client-secret" is not defined"`, method)
	}

	err = msgs.Error()
	return
}

//----------------------------------------------------------------------------------------------------------------------------//

// Инициализация метода
func (ah *AuthHandler) Init(cfg *config.Listener) (err error) {
	ah.cfg = nil
	ah.options = nil

	methodCfg, exists := cfg.Auth.Methods[module]
	if !exists || !methodCfg.Enabled || methodCfg.Options == nil {
		return
	}

	options, ok := methodCfg.Options.(*methodOptions)
	if !ok {
		return fmt.Errorf(`options for module "%s" is "%T", expected "%T"`, module, methodCfg.Options, options)
	}

	ah.cfg = methodCfg
	ah.options = options

	if !ah.cfg.Enabled {
		return
	}

	err = ah.init()
	if err != nil {
		return
	}

	return
}

//----------------------------------------------------------------------------------------------------------------------------//

// Добавление в листенер
// Add --
func Add(http *stdhttp.HTTP) (err error) {
	return http.AddAuthHandler(
		&AuthHandler{
			http: http,
		},
	)
}

//----------------------------------------------------------------------------------------------------------------------------//

// Стандартный вызов - метод разрешен?
func (ah *AuthHandler) Enabled() bool {
	return ah.cfg != nil && ah.cfg.Enabled
}

//----------------------------------------------------------------------------------------------------------------------------//

// Стандартный вызов - получение индекса для упорядочивания в последовательности вызовов методов
func (ah *AuthHandler) Score() int {
	return ah.cfg.Score
}

//----------------------------------------------------------------------------------------------------------------------------//

// Стандартный вызов - получение имени метода и необходимости добавления realm в HTTP заголовок
func (ah *AuthHandler) WWWAuthHeader() (name string, withRealm bool) {
	return method, true
}

//----------------------------------------------------------------------------------------------------------------------------//

// Стандартный вызов - попытка аутентификации данным методом
func (ah *AuthHandler) Check(id uint64, prefix string, path string, w http.ResponseWriter, r *http.Request) (identity *auth.Identity, tryNext bool) {
	if !ah.initialized {
		auth.Log.Message(log.INFO, `[%d] Not initialized yet`, id)
		return nil, false

	}

	accessToken := ""
	refreshToken := ""

	c, err := r.Cookie(accessTokenName)
	if err == nil {
		// Есть access токен в куках
		accessToken = c.Value

		c, err = r.Cookie(refreshTokenName)
		if err == nil {
			// Есть refresh токен в куках
			refreshToken = c.Value
		} else {
			// Сбрасываем access, будем по новой логиниться (а так надо???)
			accessToken = ""
		}
	}

	// Проверяем айтентификацию
	userInfo, err := ah.check(id, prefix, path, w, r, accessToken, refreshToken, 0)

	if err != nil {
		auth.Log.Message(log.INFO, `[%d] KC login error: %s`, id, err)
		return nil, false
	}

	if userInfo != nil {
		// Успешно!
		return &auth.Identity{
				Method: module,
				User:   userInfo.UserName,
				Groups: userInfo.Groups,
				Extra:  userInfo,
			},
			false
	}

	return nil, false
}

//----------------------------------------------------------------------------------------------------------------------------//

// Проверка аутентификации
func (ah *AuthHandler) check(id uint64, prefix string, path string, w http.ResponseWriter, r *http.Request, accessToken string, refreshToken string, iter int) (userInfo *kcUserInfo, err error) {
	var session *sessionData
	sessionSign := ""
	logoutNeeded := true

	defer func() {
		if err != nil {
			// Не получилось

			auth.Log.Message(log.DEBUG, "[%d] %s", id, err)

			if sessionSign != "" {
				// Удаляем их кэша
				ah.sessionsMutex.Lock()
				delete(ah.sessions, sessionSign)
				ah.sessionsMutex.Unlock()
			}

			baseURL := ah.baseURL(r)

			referer := url.QueryEscape(
				misc.NormalizeSlashes(
					fmt.Sprintf("%s/%s", baseURL, r.URL.RequestURI()),
				),
			)

			if logoutNeeded {
				// Если нужен logout
				w.Header().Set("Location", misc.NormalizeSlashes(fmt.Sprintf("%s/%s?referer=%s&token=%s", baseURL, ah.logoutRedirectPath, referer, accessToken)))
				w.WriteHeader(http.StatusFound)
				return
			}

			// пробуем обновить токен
			accessToken, refreshToken = ah.tryToRefresh(id, w, r, refreshToken)

			if accessToken == "" {
				// токен не обновлён
				oa := ah.oaConfig(baseURL, r)
				w.Header().Set("Location", oa.AuthCodeURL(fmt.Sprintf("%s%s", ah.uuid, referer)))
				w.WriteHeader(http.StatusFound)
				return
			}

			if iter > 0 {
				err = fmt.Errorf("auth loop detected")
				return
			}

			// Может получилось обновиться?
			iter++
			userInfo, err = ah.check(id, prefix, path, w, r, accessToken, refreshToken, iter)
		}
	}()

	if accessToken == "" {
		err = fmt.Errorf("empty token")
		// не будем делать logout, а попробуем сразу залогиниться
		logoutNeeded = false
		return
	}

	parts := strings.SplitN(accessToken, ".", 3)
	if len(parts) != 3 {
		err = fmt.Errorf("illegal token format: %s", accessToken)
		return
	}

	sessionSign = parts[2]

	ah.sessionsMutex.RLock()
	session, exists := ah.sessions[sessionSign]
	ah.sessionsMutex.RUnlock()

	if exists {
		if misc.NowUnix() >= session.validBefore {
			err = fmt.Errorf("session expired")
			// возможно, что токен можно еще продлить, не будем пока делать logout
			logoutNeeded = false
			return
		}

		userInfo = session.UserInfo
		return
	}

	session = &sessionData{
		RefreshToken: refreshToken,
		TokenInfo:    jwt.MapClaims{},
	}

	userInfo, err = ah.userInfo(accessToken)
	if err != nil {
		err = fmt.Errorf("get user info error: %s", err)
		// возможно, что токен можно еще продлить, не будем пока делать logout
		logoutNeeded = false
		return
	}

	_, err = jwt.ParseWithClaims(accessToken, &session.TokenInfo,
		func(*jwt.Token) (interface{}, error) {
			return ah.kcPubKey, nil
		},
	)
	if err != nil {
		return
	}

	if ah.options.CheckACR {
		// Если в конфиге разрешена проверка способа обновления (мы сами или автоматом)
		// По хорошему надо, но это при нормальной настроке доменных имен, а при хождении по IP могут быль нюансы и придется отключить.

		var acr int64
		acr, err = misc.Iface2Int(session.TokenInfo["acr"])
		if err != nil {
			err = fmt.Errorf("bad token.acr")
			return
		}

		if acr == 0 {
			// это говорит о том, что токен нам обновили, но без нашего запроса, это legacy метод, лучше перелогинимся
			err = fmt.Errorf("token.acr == 0")
			return
		}
	}

	// Получем время, до которого нам выдали токен
	exp, err := misc.Iface2Int(session.TokenInfo["exp"])
	if err != nil {
		err = fmt.Errorf("bad token.exp")
		return
	}

	session.validBefore = exp
	session.UserInfo = userInfo

	ah.sessionsMutex.Lock()
	ah.sessions[sessionSign] = session
	ah.sessionsMutex.Unlock()

	return
}

//----------------------------------------------------------------------------------------------------------------------------//

// Попытка обновить токен
func (ah *AuthHandler) tryToRefresh(id uint64, w http.ResponseWriter, r *http.Request, refreshToken string) (newAccessToken string, newRefreshToken string) {
	if refreshToken == "" {
		// refresh токена нет - увы...
		return
	}

	// Обновляемся
	newAccessToken, newRefreshToken, err := ah.refreshToken(refreshToken)

	if err != nil {
		auth.Log.Message(log.DEBUG, "[%d] tryToRefresh: %s", id, err)
		return
	}

	// Успешно, ставим куки с токенами
	w.Header().Add("Set-Cookie", fmt.Sprintf("%s=%s; path=/; domain=%s;", accessTokenName, newAccessToken, ah.options.Domain))
	w.Header().Add("Set-Cookie", fmt.Sprintf("%s=%s; path=/; domain=%s;", refreshTokenName, newRefreshToken, ah.options.Domain))

	// будем надеяться, что наши куки дальше не потрут
	// иначе надо раскоментаривать следующие две строки, что приведет к редиректу, а это, в числе прочего, нехорошо для POST
	//w.Header().Set("Location", referer)
	//w.WriteHeader(http.StatusFound)

	return

}

//----------------------------------------------------------------------------------------------------------------------------//

// Ответ при ошибке
func (ah *AuthHandler) errorReply(id uint64, w http.ResponseWriter, r *http.Request, httpCode int, message string, p ...interface{}) {
	message = fmt.Sprintf(message, p...)

	msg := struct {
		Message string `json:"error"`
	}{
		Message: message,
	}
	stdhttp.SendJSON(w, r, httpCode, msg)

	auth.Log.Message(log.DEBUG, `[%d] Reply: %d - "%s"`, id, httpCode, message)
}

//----------------------------------------------------------------------------------------------------------------------------//

/*
Нам надо получить доступный с других хостов URL, так как в общем случае KC сервер стоит отдельно и если исходный
запрос пришел на localhost или 127.0.0.1, то KC будет на себя редиректить.
Поэтому если исходный запрос локальный, то передаем KC наш внешний адрес или доменное имя.
*/
func (ah *AuthHandler) baseURL(r *http.Request) (newURL string) {
	h := r.Header

	host := h.Get("X-Forwarded-Host")
	if host == "" {
		// Это не через nginx. Получаем необходимые данные из запроса.

		// Протокол
		proto := "http"
		if r.TLS != nil {
			proto = "https"
		}

		host = r.Host
		if isLocal(host) {
			// Прилетели с локалхоста

			// Получаем порт
			port := ""
			portDlm := ""
			pp := strings.SplitN(host, ":", 2)
			if len(pp) == 2 {
				port = pp[1]
				portDlm = ":"
			}

			// И преобразуем на доменное имя или внешний адрес, в зависимости от того, что лежит в настроках
			host = ah.options.Domain
			newURL = fmt.Sprintf("%s://%s%s%s", proto, host, portDlm, port)
			return
		}

		// Формируем нужный URL
		newURL = fmt.Sprintf("%s://%s", proto, host)
		return
	}

	// Через nginx

	if isLocal(host) {
		// Локальный запрос - подменяем хост
		host = ah.options.Domain
	}

	// Получаем порт
	port := h.Get("X-Forwarded-Port")
	portDlm := ""
	if port != "" {
		portDlm = ":"
	}

	// Формируем нужный URL
	newURL = misc.NormalizeSlashes(fmt.Sprintf("%s://%s%s%s", h.Get("X-Forwarded-Proto"), host, portDlm, port))
	return
}

//----------------------------------------------------------------------------------------------------------------------------//

// Получение копии OA конфига, как как RedirectURL зависит от исходного запроса
func (ah *AuthHandler) oaConfig(baseURL string, r *http.Request) (oa *oauth2.Config) {
	prefix := ""
	if r.Header.Get("X-Forwarded-Host") != "" {
		prefix = ah.http.Config().ProxyPrefix
	}

	cfg := ah.oauth2ConfigPattern // делаем копию
	oa = &cfg

	oa.RedirectURL = misc.NormalizeSlashes(fmt.Sprintf("%s/%s/%s", baseURL, prefix, ah.callbackRedirectPath))

	return
}

//----------------------------------------------------------------------------------------------------------------------------//

// Проверка url на локальный. Пока по regexp'ам.

var (
	localHostREs = []*regexp.Regexp{
		regexp.MustCompile(`^(https?://)?localhost(\..*)?`),
		regexp.MustCompile(`^(https?://)?127(.\d{1,3}){3}(/.*)?`),
	}
)

func isLocal(url string) bool {
	for _, re := range localHostREs {
		if re.MatchString(url) {
			return true
		}
	}

	return false
}

//----------------------------------------------------------------------------------------------------------------------------//
