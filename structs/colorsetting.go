package structs

import (
	"fmt"
	"strconv"
	"strings"
)

type ColorSetting struct {
	Red   uint8 `json:"red"`
	Green uint8 `json:"green"`
	Blue  uint8 `json:"blue"`
	Alpha uint8 `json:"alpha"`
}

func (setting ColorSetting) ToString() string {
	return fmt.Sprintf("%d;%d;%d;%d", setting.Red, setting.Green, setting.Blue, setting.Alpha)
}

func ColorSettingFromString(setting string) ColorSetting {

	array := strings.Split(setting, ";")
	intarray := make([]uint8, len(array))

	for index, value := range array {
		intval, _ := strconv.Atoi(value)
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
