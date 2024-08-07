/*
Инициализация
*/
package kc

import (
	"context"
	"fmt"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/google/uuid"
	"golang.org/x/oauth2"

	"github.com/alrusov/auth"
	"github.com/alrusov/log"
	"github.com/alrusov/misc"
	"github.com/alrusov/panic"
)

//----------------------------------------------------------------------------------------------------------------------------//

func (ah *AuthHandler) init() (err error) {
	ah.uuid = uuid.NewString()

	if ah.http == nil {
		err = fmt.Errorf("HTTP is not set")
		return
	}

	// Служебыне URLs

	ah.callbackRedirectPath = "/oauth/callback"
	ah.logoutRedirectPath = "/oauth/logout"

	ah.http.AddHandler(ah, false)
	ah.http.AddEndpointsInfo(
		misc.StringMap{
			ah.callbackRedirectPath: "Callback for the Keycloack. Parameters: according to keycloak documentation",
			ah.logoutRedirectPath:   "Keycloack logout. Parameters: according to keycloak documentation",
		},
	)

	go func() {
		// Договариваемся с KC сервером

		panicID := panic.ID()
		defer panic.SaveStackToLogEx(panicID)

		var err error
		delay := time.Duration(0)
		step := 0

		for !ah.initialized && misc.AppStarted() {
			// Крутимся, пока не договоримся

			err = nil

			if delay > 0 {
				misc.Sleep(delay)
			}

			switch step {
			case 0:
				// Получаем общий конфиг от сервера
				err = ah.loadClientConfig()

			case 1:
				// Получаем публичный ключ от сервера
				var tryAgain bool
				tryAgain, err = ah.loadPubKey()
				if err != nil && !tryAgain {
					// Беда с ключом. Все плохо, Завершаем приложение.
					misc.StopApp(misc.ExServiceInitializationError)
					return
				}

			case 2:
				// Создаем провайдера
				ah.provider, err = oidc.NewProvider(context.Background(), ah.clientCfg.Issuer)

			case 3:
				// Делаем шаблон конфига
				ah.oauth2ConfigPattern = oauth2.Config{
					ClientID:     ah.options.ClientID,
					ClientSecret: ah.options.ClientSecret,
					Endpoint:     ah.provider.Endpoint(),
					RedirectURL:  "", // формируется индивидуально
					Scopes:       []string{oidc.ScopeOpenID},
				}

				// И создаем верифаера
				ah.verifier = ah.provider.Verifier(&oidc.Config{ClientID: ah.options.ClientID})
				auth.Log.Message(log.INFO, "[kc.init] Succesfully")

			case 4:
				// Всё готово. Отдельным шагом, чтобы проще было что-то еще добавить, если потребуется.
				ah.initialized = true
			}

			if err != nil {
				auth.Log.Message(log.ERR, "[kc.init] %s", err)
				delay = 5 * time.Second
				continue
			}

			delay = 0
			step++
		}
	}()

	// Инициализируем список сессий
	ah.sessions = map[string]*sessionData{}

	go func() {
		// Чистильщик устаревших сессий

		panicID := panic.ID()
		defer panic.SaveStackToLogEx(panicID)

		for misc.AppStarted() {
			now := misc.NowUnix()
			ah.Lock()

			for n, v := range ah.sessions {
				if now > v.validBefore {
					delete(ah.sessions, n)
				}
			}

			ah.Unlock()

			misc.Sleep(60 * time.Second)
		}
	}()

	return
}

//----------------------------------------------------------------------------------------------------------------------------//
