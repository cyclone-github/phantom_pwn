package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/syndtr/goleveldb/leveldb"
)

/*
Cyclone's Phantom Vault Extractor
https://github.com/cyclone-github/phantom_pwn
POC tool to extract Phantom vault wallets
This tool is proudly the first Phantom Vault Extractor
coded by cyclone in Go

GNU General Public License v2.0
https://github.com/cyclone-github/phantom_pwn/blob/main/LICENSE

version history
v0.1.0-2024-04-16; initial release
v0.2.0-2024-04-22-1500; add support for older vaults
*/

// clear screen function
func clearScreen() {
	switch runtime.GOOS {
	case "linux", "darwin":
		cmd := exec.Command("clear")
		cmd.Stdout = os.Stdout
		cmd.Run()
	case "windows":
		cmd := exec.Command("cmd", "/c", "cls")
		cmd.Stdout = os.Stdout
		cmd.Run()
	}
}

// version func
func versionFunc() {
	fmt.Fprintln(os.Stderr, "Cyclone's Phantom Vault Extractor v0.2.0-2024-04-22-1500\nhttps://github.com/cyclone-github/phantom_pwn\n")
}

// help func
func helpFunc() {
	versionFunc()
	str := `Example Usage:
./phantom_extractor.bin [-version] [-help] [phantom_vault_dir]
./phantom_extractor.bin ldeveldb/

Note: Phantom Vault Dir location on Linux with Chrome:
/home/$USER/.config/google-chrome/Default/Local\ Extension\ Settings/bfnaelmomeimhlpmgjnjophhpkkoljpa/`
	fmt.Fprintln(os.Stderr, str)
}

// print welcome screen
func printWelcomeScreen() {
	fmt.Println(" ----------------------------------------------------- ")
	fmt.Println("|        Cyclone's Phantom Vault Hash Extractor       |")
	fmt.Println("|        Use Phantom Vault Decryptor to decrypt       |")
	fmt.Println("|    https://github.com/cyclone-github/phantom_pwn    |")
	fmt.Println(" ----------------------------------------------------- ")
}

// struct for Phantom vaults
type EncryptedKey struct {
	Digest     string `json:"digest"`
	Encrypted  string `json:"encrypted"`
	Iterations int    `json:"iterations"`
	Kdf        string `json:"kdf"`
	Nonce      string `json:"nonce"`
	Salt       string `json:"salt"`
}

// vault format "version_0"
type Vault_0 struct {
	Expiry float64 `json:"expiry"`
	Value  string  `json:"value"`
}

// vault format "version_1"
type Vault_1 struct {
	EncryptedKey EncryptedKey `json:"encryptedKey"`
	Version      int          `json:"version"`
}

// processLevelDB with version handling
func processLevelDB(data []byte) {
	// detect vault version
	version := detectVersion(data)

	switch version {
	case 1: // vault version_1
		var vault_1 Vault_1
		if err := json.Unmarshal(data, &vault_1); err == nil {
			printJSONVault(vault_1)
		}
	case 0: // vault version_0
		var vault_0 Vault_0
		if err := json.Unmarshal(data, &vault_0); err == nil {
			cleanStr := strings.ReplaceAll(vault_0.Value, `\`, "") // remove "\" so json can be unmarshaled
			var encryptedKey EncryptedKey
			if err := json.Unmarshal([]byte(cleanStr), &encryptedKey); err == nil {
				vault_0 := Vault_1{
					EncryptedKey: encryptedKey,
					Version:      0, // mark as version_0 to keep backwards compatibility with phantom_decryptor
				}
				printJSONVault(vault_0)
			}
		}
	default:
		// do nothing
	}
}

// print valid JSON vaults
func printJSONVault(entry Vault_1) {
	// sanity check if vault is valid (not empty)
	if entry.EncryptedKey.Digest != "" && entry.EncryptedKey.Encrypted != "" && entry.EncryptedKey.Iterations != 0 &&
		entry.EncryptedKey.Kdf != "" && entry.EncryptedKey.Nonce != "" && entry.EncryptedKey.Salt != "" {
		entryJSON, err := json.Marshal(entry)
		if err != nil {
			fmt.Println("Error marshalling entry to JSON:", err)
			return
		}
		fmt.Println(string(entryJSON))
	}
}

// vault version detection
func detectVersion(data []byte) int {
	if strings.Contains(string(data), "\"encryptedKey\":") {
		return 1
	} else if strings.Contains(string(data), "\"expiry\":") {
		return 0
	}
	return -1 // unknown version
}

// main
func main() {
	cycloneFlag := flag.Bool("cyclone", false, "")
	versionFlag := flag.Bool("version", false, "Program version")
	helpFlag := flag.Bool("help", false, "Program usage instructions")
	flag.Parse()

	clearScreen()

	// run sanity checks for special flags
	if *versionFlag {
		versionFunc()
		os.Exit(0)
	}
	if *cycloneFlag {
		line := "Q29kZWQgYnkgY3ljbG9uZSA7KQo="
		str, _ := base64.StdEncoding.DecodeString(line)
		fmt.Println(string(str))
		os.Exit(0)
	}
	if *helpFlag {
		helpFunc()
		os.Exit(0)
	}

	ldbDir := flag.Arg(0)
	if ldbDir == "" {
		fmt.Fprintln(os.Stderr, "Error: Phantom vault directory is required")
		os.Exit(1)
	}

	db, err := leveldb.OpenFile(ldbDir, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to open Vault:", err)
		os.Exit(1)
	}
	defer db.Close()

	printWelcomeScreen()

	iter := db.NewIterator(nil, nil)
	defer iter.Release()
	for iter.Next() {
		value := iter.Value()
		processLevelDB(value)
	}
}

// end code
