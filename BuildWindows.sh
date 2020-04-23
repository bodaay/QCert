#!/bin/bash
GOOS=windows GOARCH=amd64 go build -o output/windows/x64/QCert_x64.exe .
GOOS=windows GOARCH=386 go build -o output/windows/x86/QCert_x86.exe .