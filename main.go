package main

import (
	"encoding/base32"
	"fmt"
	"go-tiny-mfa/core"
	"go-tiny-mfa/middleware"
	"log"
)

func main() {
	db := middleware.CreateConnection()
	defer middleware.CloseConnection(db)
	//ts := time.Now().Unix()
	ts := int64(1592485571800)
	keyStr := "NOU4XWWCB4ZJOPNZRF6WRTFRMQ======"

	key, err := base32.StdEncoding.DecodeString(keyStr)
	if err != nil {
		log.Fatal(err)
	}

	token, err := core.GenerateValidToken(ts, key, core.OffsetTypePresent)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(token)

}
