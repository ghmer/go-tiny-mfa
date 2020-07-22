package main

import (
	"encoding/base32"
	"fmt"
	"go-tiny-mfa/core"
	"go-tiny-mfa/qrcode"
	"go-tiny-mfa/structs"
	"time"
)

func cleanup() {
	fmt.Println("Cleanup called")
}
func main() {
	/*
			var connURL string = os.Args[1]
			var port string = os.Args[2]

			db := middleware.CreateConnection(connURL)
			defer middleware.CloseConnection(db)

			c := make(chan os.Signal)
			signal.Notify(c, os.Interrupt, syscall.SIGTERM)
			go func() {
				<-c
				cleanup()
				middleware.CloseConnection(db)
				os.Exit(1)
			}()

			r := router.Router()
			// fs := http.FileServer(http.Dir("build"))
			// http.Handle("/", fs)
			fmt.Println(fmt.Sprintf("Start serving on port %s", port))
			log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", port), r))


		key, err := core.GenerateStandardSecretKey()
		if err != nil {
			fmt.Println(err)
		}

		str := base32.StdEncoding.EncodeToString(key)
		fmt.Println(str)

		key, err = core.GenerateExtendedSecretKey()
		if err != nil {
			fmt.Println(err)
		}

		str = base32.StdEncoding.EncodeToString(key)
		fmt.Println(str)

			16
			D5WZMKC5I3FDIW7FXG6P2KSVGA======
			32
			KWHWKSJJY7TXIDWAUHHAVAV3YULTW3ERZ6ZVUGZ7F46HBMVLTFZA====
	*/

	key, err := base32.StdEncoding.DecodeString("KWHWKSJJY7TXIDWAUHHAVAV3YULTW3ERZ6ZVUGZ7F46HBMVLTFZA====")
	if err != nil {
		fmt.Println(err)
	}

	fmt.Printf("% x\n", key)

	user := structs.User{Username: "mario", Issuer: "issuer.net", Base32Key: key}

	qrcode.WriteQrCodeImage(user, "/tmp/image.png")

	fmt.Println(core.GenerateValidToken(time.Now().Unix(), user.Base32Key, 0))
	fmt.Println(core.ValidateTokenCurrentTimestamp(248440, user.Base32Key))

}
