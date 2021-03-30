package structs

type QrCodeConfig struct {
	BgColor ColorSetting `json:"qrcode-bgcolor"`
	FgColor ColorSetting `json:"qrcode-fgcolor"`
}

//StandardQrCodeConfig returns a standard qrcode configuration
func StandardQrCodeConfig() QrCodeConfig {
	var config QrCodeConfig = QrCodeConfig{
		BgColor: ColorSetting{Red: 255, Green: 255, Blue: 255, Alpha: 255},
		FgColor: ColorSetting{Red: 0, Green: 0, Blue: 0, Alpha: 255},
	}
	return config
}
