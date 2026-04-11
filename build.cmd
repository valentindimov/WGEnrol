@echo off
set GOOS=linux
set GOARCH=amd64
go build -o build\wgenrol_x86-64
set GOARCH=arm64
go build -o build\wgenrol_arm64
