# Phantom Vault Extractor & Decryptor
### POC tools to extract and decrypt Phantom vaults
_**This toolset is proudly the first publicly released Phantom Vault Extractor and Decryptor**_
### Phantom vault location for Chrome extensions:
- Linux: `/home/$USER/.config/google-chrome/Default/Local\ Extension\ Settings/bfnaelmomeimhlpmgjnjophhpkkoljpa/`
- Mac: `Library>Application Support>Google>Chrome>Default>Local Extension Settings>bfnaelmomeimhlpmgjnjophhpkkoljpa`
- Windows: `C:\Users\$USER\AppData\Local\Google\Chrome\User Data\Default\Local Extension Settings\bfnaelmomeimhlpmgjnjophhpkkoljpa\`
### Extractor usage example on test vault: (plaintext is `password`)
```
./phantom_extractor.bin bfnaelmomeimhlpmgjnjophhpkkoljpa/
 ----------------------------------------------------- 
|        Cyclone's Phantom Vault Hash Extractor       |
|        Use Phantom Vault Decryptor to decrypt       |
|    https://github.com/cyclone-github/phantom_pwn    |
 ----------------------------------------------------- 
{"encryptedKey":{"digest":"sha256","encrypted":"5pLvA3bCjNGYBbSjjFY3mdPknwFfp3cz9dCBv6izyyrqEhYCBkKwo3zZUzBP44KtY3","iterations":10000,"kdf":"pbkdf2","nonce":"NZT6kw5Cd5VeZu5yJGJcFcP24tnmg4xsR","salt":"A43vTZnm9c5CiQ6FLTdV9v"},"version":1}
```
### Decryptor usage example:
```
./phantom_decryptor.bin -h phantom.txt -w wordlist.txt
 ----------------------------------------------- 
|       Cyclone's Phantom Vault Decryptor       |
| https://github.com/cyclone-github/phantom_pwn |
 ----------------------------------------------- 

Vault file:     phantom.txt
Valid Vaults:   1
CPU Threads:    16
Wordlist:       wordlist.txt
Working...

Decrypted: 0/1  6360.82 h/s     00h:01m:00s
```
### Decryptor supported options:
```
-w {wordlist} (omit -w to read from stdin)
-h {phantom_wallet_hash}
-o {output} (omit -o to write to stdout)
-t {cpu threads}
-s {print status every nth sec}

-version (version info)
-help (usage instructions)

./phantom_decryptor.bin -h {phantom_wallet_hash} -w {wordlist} -o {output} -t {cpu threads} -s {print status every nth sec}

./phantom_decryptor.bin -h phantom.txt -w wordlist.txt -o cracked.txt -t 16 -s 10

cat wordlist | ./phantom_decryptor.bin -h phantom.txt

./phantom_decryptor.bin -h phantom.txt -w wordlist.txt -o output.txt
```
### Decryptor credits:
- Shoutout to blandyuk for his help with research - https://github.com/blandyuk
- https://github.com/renfeee/spl-token-wallet/blob/master/src/utils/wallet-seed.js

### Compile from source:
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
