package structs

import (
	"fmt"
	"strconv"
	"strings"
)

// QrCodeConfig represents the configuration for a QR code.
type QrCodeConfig struct {
	BgColor ColorSetting `json:"qrcode-bgcolor"`
	FgColor ColorSetting `json:"qrcode-fgcolor"`
}

// StandardQrCodeConfig returns a standard qrcode configuration
func StandardQrCodeConfig() QrCodeConfig {
	var config QrCodeConfig = QrCodeConfig{
		BgColor: ColorSetting{Red: 255, Green: 255, Blue: 255, Alpha: 255},
		FgColor: ColorSetting{Red: 0, Green: 0, Blue: 0, Alpha: 255},
	}
	return config
}

// ColorSetting represents a color setting with RGBA values.
type ColorSetting struct {
	Red   uint8 `json:"red"`
	Green uint8 `json:"green"`
	Blue  uint8 `json:"blue"`
	Alpha uint8 `json:"alpha"`
}

// ToString converts a ColorSetting struct to a string. The format is "red;green;blue;alpha".
func (setting *ColorSetting) ToString() string {
	return fmt.Sprintf("%d;%d;%d;%d", setting.Red, setting.Green, setting.Blue, setting.Alpha)
}

// ColorSettingFromString converts a string to a ColorSetting struct. The string should be in the format "red;green;blue;alpha".
func ColorSettingFromString(setting string) ColorSetting {

	array := strings.Split(setting, ";")
	intarray := make([]uint8, len(array))

	for index, value := range array {
		//trying to parse uint value
		intval, err := strconv.ParseUint(value, 10, 8)
		if err != nil {
			failint, err := strconv.Atoi(value)
			if err != nil {
				intval = 0
			} else {
				if failint < 0 {
					intval = 0
				}
				if failint > 255 {
					intval = 255
				}
			}
		}
		intarray[index] = uint8(intval)
	}

	var settingStruct ColorSetting = ColorSetting{
		Red:   intarray[0],
		Green: intarray[1],
		Blue:  intarray[2],
		Alpha: intarray[3],
	}
	return settingStruct
}
