package kc

import (
	"testing"
)

//----------------------------------------------------------------------------------------------------------------------------//

func TestIsLocal(t *testing.T) {
	params := []struct {
		url   string
		local bool
	}{
		{url: "127.0.0.1", local: true},
		{url: "127.1.2.3", local: true},
		{url: "127.domain.com", local: false},
		{url: "192.168.1.1", local: false},
		{url: "localhost", local: true},
		{url: "localhost.localdomain", local: true},
		{url: "localhost.", local: true},
		{url: "localhost.domain.com", local: true}, // предполагается, что DNS настраивал адекватный человек
		{url: "domain", local: false},
		{url: "domain.com", local: false},

		{url: "https://127.0.0.1", local: true},
		{url: "http://127.1.2.3", local: true},
		{url: "https://127.domain.com", local: false},
		{url: "http://192.168.1.1", local: false},
		{url: "http://localhost", local: true},
		{url: "https://localhost.localdomain", local: true},
		{url: "http://localhost.", local: true},
		{url: "https://localhost.domain.com", local: true}, // предполагается, что DNS настраивал адекватный человек
		{url: "http://domain", local: false},
		{url: "https://domain.com", local: false},

		{url: "https://127.0.0.1/", local: true},
		{url: "http://127.1.2.3/", local: true},
		{url: "https://127.domain.com/", local: false},
		{url: "http://192.168.1.1/", local: false},
		{url: "http://localhost/", local: true},
		{url: "https://localhost.localdomain/", local: true},
		{url: "http://localhost./", local: true},
		{url: "https://localhost.domain.com/", local: true}, // предполагается, что DNS настраивал адекватный человек
		{url: "http://domain/", local: false},
		{url: "https://domain.com/", local: false},

		{url: "https://127.0.0.1/qqq/www", local: true},
		{url: "http://127.1.2.3/qqq/www", local: true},
		{url: "https://127.domain.com/qqq/www", local: false},
		{url: "http://192.168.1.1/qqq/www", local: false},
		{url: "http://localhost/qqq/www", local: true},
		{url: "https://localhost.localdomain/qqq/www", local: true},
		{url: "http://localhost./qqq/www", local: true},
		{url: "https://localhost.domain.com/qqq/www", local: true}, // предполагается, что DNS настраивал адекватный человек
		{url: "http://domain/qqq/www", local: false},
		{url: "https://domain.com/qqq/www", local: false},
	}

	for i, p := range params {
		i++
		local := isLocal(p.url)
		if local != p.local {
			t.Errorf(`[%d] "%s": got %v, expected %v`, i, p.url, local, p.local)
		}
	}
}

//----------------------------------------------------------------------------------------------------------------------------//
