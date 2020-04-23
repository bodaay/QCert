set GOOS=linux
set GOARCH=amd64
go build -o output/linux/x64/QCert .
set GOOS=linux
set GOARCH=386
go build -o output/linux/x86/QCert .
set GOOS=linux
set GOARCH=arm
go build -o output/linux/arm/QCert .
set GOOS=""
set GOARCH=""