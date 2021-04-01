package structs

//OidcConfig is a struct containing the current oidc configuration
type OidcConfig struct {
	ID           uint8  `json:"id"`
	Enabled      bool   `json:"enabled"`
	ClientID     string `json:"client-id"`
	ClientSecret string `json:"client-secret"`
	DiscoveryURL string `json:"discovery-url"`
}
