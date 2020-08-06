package structs

import "github.com/google/uuid"

//ServerConfig is a struct that holds a server configuration
type ServerConfig struct {
	RouterPort   uint16 `json:"http_port"`
	DenyLimit    uint8  `json:"deny_limit"`
	RootToken    string `json:"root_token"`
	VerifyTokens bool   `json:"verify_tokens"`
	TokenLength  uint8  `json:"token_length"`
}

//StandardServerConfig returns a standard server configuration
func StandardServerConfig() ServerConfig {
	var config ServerConfig = ServerConfig{
		RouterPort:   57687,
		DenyLimit:    5,
		RootToken:    uuid.New().String(),
		VerifyTokens: false,
		TokenLength:  6,
	}
	return config
}
