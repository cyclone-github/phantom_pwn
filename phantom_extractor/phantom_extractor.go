package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"runtime"

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
	fmt.Fprintln(os.Stderr, "Cyclone's Phantom Vault Extractor v0.1.0-2024-04-16\nhttps://github.com/cyclone-github/phantom_pwn\n")
}

// help func
func helpFunc() {
	versionFunc()
	str := `Example Usage:
./phantom_extractor.bin [-version] [-help] [phantom_vault_dir]
./phantom_extractor.bin ldeveldb/

Note: Phantom Vault Dir location on Linux with Chrome:
/home/{username}/.config/google-chrome/Default/Local Extension Settings/bfnaelmomeimhlpmgjnjophhpkkoljpa/`
	fmt.Fprintln(os.Stderr, str)
}

// print welcome screen
func printWelcomeScreen() {
	fmt.Println(" ---------------------------------------------------- ")
	fmt.Println("|        Cyclone's Phantom Vault Hash Extractor       |")
	fmt.Println("|        Use Phantom Vault Decryptor to decrypt       |")
	fmt.Println("|    https://github.com/cyclone-github/phantom_pwn    |")
	fmt.Println(" ---------------------------------------------------- ")
}

// define structs
type EncryptedKey struct {
	Digest     string `json:"digest"`
	Encrypted  string `json:"encrypted"`
	Iterations int    `json:"iterations"`
	Kdf        string `json:"kdf"`
	Nonce      string `json:"nonce"`
	Salt       string `json:"salt"`
}

type Entry struct {
	EncryptedKey EncryptedKey `json:"encryptedKey"`
	Version      int          `json:"version"`
}

// print JSON structure if encryptedKey is found
func processEncryptedKeyData(data []byte) {
	var entry Entry
	if err := json.Unmarshal(data, &entry); err == nil {
		if entry.EncryptedKey.Encrypted != "" {
			printWelcomeScreen()
			entryJSON, err := json.Marshal(entry)
			if err != nil {
				fmt.Println("Error marshalling entry to JSON:", err)
				return
			}
			fmt.Println(string(entryJSON))
		}
	}
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

	iter := db.NewIterator(nil, nil)
	defer iter.Release()
	for iter.Next() {
		value := iter.Value()
		processEncryptedKeyData(value)
	}
}

// end code
