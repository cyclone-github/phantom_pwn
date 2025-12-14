[![Readme Card](https://github-readme-stats-fast.vercel.app/api/pin/?username=cyclone-github&repo=phantom_pwn&theme=gruvbox)](https://github.com/cyclone-github/phantom_pwn/)

[![GitHub issues](https://img.shields.io/github/issues/cyclone-github/phantom_pwn.svg)](https://github.com/cyclone-github/phantom_pwn/issues)
[![License](https://img.shields.io/github/license/cyclone-github/phantom_pwn.svg)](LICENSE)
[![GitHub release](https://img.shields.io/github/release/cyclone-github/phantom_pwn.svg)](https://github.com/cyclone-github/phantom_pwn/releases)

# Phantom Vault Extractor & Decryptor

### Install phantom_extractor:
```
go install github.com/cyclone-github/phantom_pwn/phantom_extractor@main
```
### Install phantom_decryptor:
```
go install github.com/cyclone-github/phantom_pwn/phantom_decryptor@main
```

### POC tools to recover, extract and decrypt Phantom vaults
_**This toolset is proudly the first publicly released Phantom Vault Extractor and Decryptor**_
- Contact me at https://forum.hashpwn.net/user/cyclone if you need help recovering your Phantom wallet password or seed phrase
- Note: `phantom_extractor` supports hashcat modes 30010, 26650, and 26651 for convenience, but these are third-party modules that are not affiliated with or included in the official hashcat beta or release builds at https://github.com/hashcat/hashcat

### Writeup of my process of decrypting Phantom Wallets and recovering the seed phrase
- https://github.com/cyclone-github/writeups/blob/main/Pwning%20Phantom%20Wallets.pdf
  
### Phantom vault location for Chrome extensions:
- Linux: `/home/$USER/.config/google-chrome/Default/Local\ Extension\ Settings/bfnaelmomeimhlpmgjnjophhpkkoljpa/`
- Mac: `Library>Application Support>Google>Chrome>Default>Local Extension Settings>bfnaelmomeimhlpmgjnjophhpkkoljpa`
- Windows: `C:\Users\$USER\AppData\Local\Google\Chrome\User Data\Default\Local Extension Settings\bfnaelmomeimhlpmgjnjophhpkkoljpa\`
### Extractor usage example on test vault: (plaintext is `password`)
* Old pbkdf2 KDF
```
./phantom_extractor.bin bfnaelmomeimhlpmgjnjophhpkkoljpa/
 ----------------------------------------------------- 
|        Cyclone's Phantom Vault Hash Extractor       |
|        Use Phantom Vault Decryptor to decrypt       |
|    https://github.com/cyclone-github/phantom_pwn    |
 ----------------------------------------------------- 
{"encryptedKey":{"digest":"sha256","encrypted":"5pLvA3bCjNGYBbSjjFY3mdPknwFfp3cz9dCBv6izyyrqEhYCBkKwo3zZUzBP44KtY3","iterations":10000,"kdf":"pbkdf2","nonce":"NZT6kw5Cd5VeZu5yJGJcFcP24tnmg4xsR","salt":"A43vTZnm9c5CiQ6FLTdV9v"},"version":1}
 ----------------------------------------------------- 
|          hashcat -m 30010 hash (pbkdf2 kdf)         |
 ----------------------------------------------------- 
$phantom$SU9HoVMjb1ieOEv18nz3FQ==$7H29InVRWVbHS4WcBJdTay0ONb4mLX9Q$g0vJAbflhH4jJJDvuv7Ar5THgzBmJ8tt6oajsQZd/dSXNNjcY5/0eGeF5c1NW1WU
 ----------------------------------------------------- 
|          hashcat -m 26651 hash (pbkdf2 kdf)         |
 ----------------------------------------------------- 
PHANTOM:10000:SU9HoVMjb1ieOEv18nz3FQ==:7H29InVRWVbHS4WcBJdTay0ONb4mLX9Q:g0vJAbflhH4jJJDvuv7Ar5THgzBmJ8tt6oajsQZd/dSXNNjcY5/0eGeF5c1NW1WU
```
* New scrypt KDF
```
./phantom_extractor.bin bfnaelmomeimhlpmgjnjophhpkkoljpa/
 ----------------------------------------------------- 
|        Cyclone's Phantom Vault Hash Extractor       |
|        Use Phantom Vault Decryptor to decrypt       |
|    https://github.com/cyclone-github/phantom_pwn    |
 ----------------------------------------------------- 
{"encryptedKey":{"digest":"sha256","encrypted":"37fJoKsB9vwnKEzPgc2AHtYVsPTTzrXdTGacbgWxLxbiS7Ri3P3iNnf8csaKwJ4wpk","iterations":10000,"kdf":"scrypt","nonce":"49aomus4HiKLyg7F66pSinR4tpuUuJDHX","salt":"M1PMFn4p4gdCxZDzf8qX71"},"version":1}
 ----------------------------------------------------- 
|          hashcat -m 26650 hash (scrypt kdf)         |
 ----------------------------------------------------- 
PHANTOM:4096:8:1:ogSL4J4xP/wNbAjiA8Q4hA==:Iofs3VYyyaYFzHVkcMsnpkrjGQ2+Kni2:OacHaTJAM8dD7XJIj5bGMU3cM8QW3u92n+ngYjXsgRSR20FDnkMLQHTgPxJDefOx

```
### Decryptor usage example:
```
 ----------------------------------------------- 
|       Cyclone's Phantom Vault Decryptor       |
| https://github.com/cyclone-github/phantom_pwn |
 ----------------------------------------------- 

Vault file:     hash.txt
Valid Vaults:   1
CPU Threads:    16
Wordlist:       wordlist.txt
2025/10/22 14:11:35 Working...
{"encryptedKey":{"digest":"sha256","encrypted":"5pLvA3bCjNGYBbSjjFY3mdPknwFfp3cz9dCBv6izyyrqEhYCBkKwo3zZUzBP44KtY3","iterations":10000,"kdf":"pbkdf2","nonce":"NZT6kw5Cd5VeZu5yJGJcFcP24tnmg4xsR","salt":"A43vTZnm9c5CiQ6FLTdV9v"},"version":1}:password
2025/10/22 14:11:39 Decrypted: 1/1 6181.36 h/s 00h:00m:03s

2025/10/22 14:11:39 Finished

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
  - `git clone https://github.com/cyclone-github/phantom_pwn.git` # clone repo
  - phantom_extractor
  - `cd phantom_pwn/phantom_extractor`                            # enter project directory
  - `go mod init phantom_extractor`                                # initialize Go module (skips if go.mod exists)
  - `go mod tidy`                                                   # download dependencies
  - `go build -ldflags="-s -w" .`                                   # compile binary in current directory
  - `go install -ldflags="-s -w" .`                                 # compile binary and install to $GOPATH
  - phantom_decryptor
  - `cd phantom_pwn/phantom_decryptor`                            # enter project directory
  - `go mod init phantom_decryptor`                                # initialize Go module (skips if go.mod exists)
  - `go mod tidy`                                                   # download dependencies
  - `go build -ldflags="-s -w" .`                                   # compile binary in current directory
  - `go install -ldflags="-s -w" .`                                 # compile binary and install to $GOPATH
- Compile from source code how-to:
  - https://github.com/cyclone-github/scripts/blob/main/intro_to_go.txt
