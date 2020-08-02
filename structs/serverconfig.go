package structs

import "github.com/google/uuid"

//ServerConfig is a struct that holds a server configuration
type ServerConfig struct {
	RouterPort   uint16 `json:"http-port"`
	DenyLimit    uint8  `json:"deny-limit"`
	RootToken    string `json:"root-access-token"`
	VerifyTokens bool   `json:"verify-tokens"`
}

//StandardServerConfig returns a standard server configuration
func StandardServerConfig() ServerConfig {
	var config ServerConfig = ServerConfig{
		RouterPort:   57687,
		DenyLimit:    5,
		RootToken:    uuid.New().String(),
		VerifyTokens: false,
	}
	return config
}
