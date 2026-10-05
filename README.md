# WGEnrol
A simple Web-based application for enrolling and managing peers in a Wireguard network.
Rather than managing a Wireguard `.conf` file by hand, WGEnrol allows an administrator to easily view, edit, and remove peers from the Web UI, as well as send invite links to new peers who can also enrol using the Web frontend.
Peer private keys are generated in the browser at the time of enrolment and never shared with the backend.

WGEnrol's dependencies are intentionally minimal:
- The app is built based on simple HTML templating and sticks to the Go standard library where possible;
- In the backend, additional libraries are used for cryptography, YAML and INI format support, and Wireguard interface control;
- In the frontend, the [qrcode.js](https://github.com/davidshimjs/qrcodejs) library is included to generate QR codes for mobile Wireguard clients. See the [enrolment.html](./enrolment.html) template file.

A reasonably modern browser (one that supports the [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)) is required to use the app.


## How to Build
You will need a reasonably recent Go version (tested with 1.24). Depending on your host system, run:

```bash
./build.sh
```
on Linux, or

```powershell
.\build.cmd
```
on Windows.

The scripts produce builds for Linux and Windows (both x86 and ARM) in the `build/` directory.

You can also run `test.sh` or `test.cmd` respectively to run unit tests for some components.


## How to Run
The application uses a YAML-formatted config file. Check [testfiles/test.conf](./testfiles/test.conf) for an example.
Create this file and store it somewhere convenient, e.g. in `/etc/`.

The application manages the peer list of the Wireguard interface referenced by `wireguard.ifname` in the config file.
It does NOT create the interface, nor does it configure interface parameters like private key, IP routes, etc.
It ONLY manages the Wireguard peer list, assuming that all the rest is configured in advance, or managed by another tool.
It supports both Windows and Linux.

Additionally, peers are stored in a separate file, pointed to by `wireguard.confFile` in the YAML config.
You *can* create the interface using `wg-quick` and control the same `.conf` file using WGEnrol, but you don't have to.
The file is just used as a database to store the peers and can be completely separate from the configuration used to create the Wireguard interface itself.


## Notice on AI usage 
Though the productive code of WGEnrol is written by hand, AI coding tools are used for static verification, writing tests, and security hardening.


## License
Copyright (c) 2026 Valentin Dimov.
WGEnrol is licensed under the MIT license - see [LICENSE](./LICENSE).
