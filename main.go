package main

import (
	"fmt"
	"os"

	"github.com/bodaay/QCert/certtools"
)

func main() {
	fmt.Println("Usage: QCert [port]")
	port := "11129"
	if len(os.Args) > 1 {
		port = os.Args[1]
	}
	address := fmt.Sprintf("127.0.0.1:%s", port)
	certtools.StartWebCertTool(address)
	//This tool will only work on localhost, compile your own if you want to listen to other

}
