@echo off
REM Runs formatting check, vet, optional staticcheck, and the test suite.
REM Counterpart to build.cmd.

cd /d "%~dp0"

echo [1/4] gofmt
set FMT_BAD=
for /f "delims=" %%i in ('gofmt -l .') do (
    echo Not gofmt-clean: %%i
    set FMT_BAD=1
)
if defined FMT_BAD (
    echo Run: gofmt -w .
    exit /b 1
)

echo [2/4] go vet
go vet ./...
if errorlevel 1 exit /b 1

echo [3/4] staticcheck (optional)
where staticcheck >nul 2>nul
if %errorlevel%==0 (
    staticcheck ./...
    if errorlevel 1 exit /b 1
) else (
    echo staticcheck not installed, skipping
)

echo [4/4] go test
where gcc >nul 2>nul
if %errorlevel%==0 (
    set CGO_ENABLED=1
    go test -race ./...
) else (
    echo No C compiler found: running tests without -race
    go test ./...
)
if errorlevel 1 exit /b 1

echo OK: all checks passed.
