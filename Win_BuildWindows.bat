set GOOS=windows
set GOARCH=amd64
go build -o output/windows/x64/QCert_x64.exe .
set GOOS=windows
set GOARCH=386
go build -o output/windows/x86/QCert_x86.exe .
REM set GOOS=windows
REM set GOARCH=arm
REM go build -o output/windows/arm/OfflineSyncExporter_arm32.exe .
set GOOS=""
set GOARCH=""