# Phantom Vault Extractor & Decryptor
### POC tools to extract and decrypt Phantom vault wallets
_**This tool is proudly the first publicly released Phantom Vault extractor / decryptor.**_
### Usage example:
```
./phantom.bin -h phantom.txt -w wordlist.txt
 ----------------------------------- 
| Cyclone's Phantom Vault Decryptor |
 ----------------------------------- 

Vault file:     phantom.txt
Valid Vaults:   1
CPU Threads:    16
Wordlist:       wordlist.txt
Working...

Decrypted: 0/1  6360.82 h/s     00h:01m:00s
```

### Output example:
If the tool successfully decrypts the vault, tool will print the vault password.

### Credits
- Shoutout to blandyuk for his help with research - https://github.com/blandyuk
- https://github.com/renfeee/spl-token-wallet/blob/master/src/utils/wallet-seed.js

### Compile from source:
- If you want the latest features, compiling from source is the best option since the release version may run several revisions behind the source code.
- This assumes you have Go and Git installed
  - `git clone https://github.com/cyclone-github/phantom_pwn.git`
  - phantom_extractor
  - `cd phantom_pwn/phantom_extractor`
  - `go mod init phantom_extractor`
  - `go mod tidy`
  - `go build -ldflags="-s -w" phantom_extractor.go`
  - phantom_decryptor
  - `cd phantom_pwn/phantom_decryptor`
  - `go mod init phantom_decryptor`
  - `go mod tidy`
  - `go build -ldflags="-s -w" phantom_decryptor.go`
- Compile from source code how-to:
  - https://github.com/cyclone-github/scripts/blob/main/intro_to_go.txt
