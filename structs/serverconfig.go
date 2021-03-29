package structs

import "github.com/google/uuid"

//ServerConfig is a struct that holds a server configuration
type ServerConfig struct {
	RouterPort    uint16       `json:"http_port"`
	DenyLimit     uint8        `json:"deny_limit"`
	RootToken     string       `json:"root_token"`
	VerifyTokens  bool         `json:"verify_tokens"`
	QrCodeBgColor ColorSetting `json:"qrcode-bgcolor"`
	QrCodeFgColor ColorSetting `json:"qrcode-fgcolor"`
	SchemaVersion uint8        `json:"schema-version"`
}

//StandardServerConfig returns a standard server configuration
func StandardServerConfig() ServerConfig {
	var config ServerConfig = ServerConfig{
		RouterPort:    57687,
		DenyLimit:     5,
		RootToken:     uuid.New().String(),
		VerifyTokens:  false,
		QrCodeBgColor: ColorSetting{Red: 0, Green: 0, Blue: 0, Alpha: 0},
		QrCodeFgColor: ColorSetting{Red: 0, Green: 0, Blue: 0, Alpha: 255},
		SchemaVersion: 1,
	}
	return config
}
