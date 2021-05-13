package structs

import "regexp"

//OidcConfig is a struct containing the current oidc configuration
type OidcConfig struct {
	ID           uint8  `json:"id"`
	Enabled      bool   `json:"enabled"`
	ClientID     string `json:"client-id"`
	ClientSecret string `json:"client-secret"`
	DiscoveryURL string `json:"discovery-url"`
}

func (oidcConfig OidcConfig) IsSafe() bool {
	var urlregex string = `https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()!@:%_\+.~#?&\/\/=]*)`
	var strregex string = `^[a-zA-Z0-9_-]*$`

	if ok, _ := regexp.MatchString(strregex, oidcConfig.ClientID); !ok {
		return false
	}

	if ok, _ := regexp.MatchString(strregex, oidcConfig.ClientSecret); !ok {
		return false
	}

	if ok, _ := regexp.MatchString(urlregex, oidcConfig.DiscoveryURL); !ok {
		return false
	}
	return true
}
