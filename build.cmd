@echo off
set GOOS=linux
set GOARCH=amd64
go build -o build\basstoonvpn_x86-64
set GOARCH=arm64
go build -o build\basstoonvpn_arm64
