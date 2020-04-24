package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/bodaay/QCert/certtools"
	"github.com/bodaay/QCert/postman"
)

func main() {
	fmt.Println("Usage: QCert [127.0.0.1:11129 | 0.0.0.0:11129]")
	address := "127.0.0.1:11129"
	if len(os.Args) > 1 {
		address = os.Args[1]
	}
	//we will get postman json file unmarshalled, we are using quicktype to generate postman.go
	host := strings.Split(address, ":")[0]

	port := strings.Split(address, ":")[1]
	pm := new(postman.PostmanCollection)
	err := json.Unmarshal([]byte(postman.PostmanJsonVar), pm)
	if err != nil {
		panic(err)
	}
	//Now lets replace each url on with address
	for _, item := range pm.Item {
		for _, subitem := range item.Item {
			subitem.Request.URL.Host[0] = postman.Host(host)
			subitem.Request.URL.Port = port
			strings.Replace(subitem.Request.URL.Raw, "localhost:11129", address, 1)
		}
	}

	pmMarshalled, err := json.MarshalIndent(pm, "", "  ")
	if err != nil {
		panic(err)
	}
	err = ioutil.WriteFile("QCert_Postman_Collection.json", pmMarshalled, os.ModePerm)
	if err != nil {
		panic(err)
	}
	// address := fmt.Sprintf("127.0.0.1:%s", port)
	certtools.StartWebCertTool(address)

}
