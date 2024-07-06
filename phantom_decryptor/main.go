package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"runtime"
	"sync"
	"time"
)

/*
Cyclone's Phantom Vault Decryptor
https://github.com/cyclone-github/phantom_pwn
POC tool to decrypt Phantom Vault wallets
This tool is proudly the first Phantom Vault Decryptor / Cracker
coded by cyclone in Go

credits:
shoutout to blandyuk for his help with research - https://github.com/blandyuk
nacl/secretbox AES implementation based on https://github.com/renfeee/spl-token-wallet/blob/master/src/utils/wallet-seed.js

GNU General Public License v2.0
https://github.com/cyclone-github/phantom_pwn/blob/main/LICENSE

version history
v0.1.0-2024-04-20-2000; initial release
v0.1.1-2024-05-02-1600;
	refactor code
	fixed https://github.com/cyclone-github/phantom_pwn/issues/1
v0.1.2-2024-05-31-1700;
	acknowledged https://github.com/cyclone-github/phantom_pwn/issues/3
	added placeholder for scrypt KDF
v0.1.3-2024-07-06-1100;
	added support for scrypt KDF
	fixed https://github.com/cyclone-github/phantom_pwn/issues/3
*/

// main func
func main() {
	wordlistFileFlag := flag.String("w", "", "Input file to process (omit -w to read from stdin)")
	vaultFileFlag := flag.String("h", "", "Vault File")
	outputFile := flag.String("o", "", "Output file to write hashes to (omit -o to print to console)")
	cycloneFlag := flag.Bool("cyclone", false, "")
	versionFlag := flag.Bool("version", false, "Program version:")
	helpFlag := flag.Bool("help", false, "Prints help:")
	threadFlag := flag.Int("t", runtime.NumCPU(), "CPU threads to use (optional)")
	statsIntervalFlag := flag.Int("s", 60, "Interval in seconds for printing stats. Defaults to 60.")
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

	if *vaultFileFlag == "" {
		fmt.Fprintln(os.Stderr, "-h (vault file) flags is required")
		fmt.Fprintln(os.Stderr, "Try running with -help for usage instructions")
		os.Exit(1)
	}

	// override outputFile since this has not been implemented yet
	*outputFile = ""

	startTime := time.Now()

	// set CPU threads
	numThreads := setNumThreads(*threadFlag)

	// channels / variables
	crackedCountCh := make(chan int, 10)     // buffer of 10 to reduce blocking
	linesProcessedCh := make(chan int, 1000) // buffer of 1000 to reduce blocking
	stopChan := make(chan struct{})
	var wg sync.WaitGroup

	// goroutine to watch for ctrl+c
	handleGracefulShutdown(stopChan)

	// read vaults
	vaults, err := readVaultData(*vaultFileFlag)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error reading vault file:", err)
		os.Exit(1)
	}
	validVaultCount := len(vaults)

	// print welcome screen
	printWelcomeScreen(vaultFileFlag, wordlistFileFlag, validVaultCount, numThreads)

	// monitor status of workers
	wg.Add(1)
	go monitorPrintStats(crackedCountCh, linesProcessedCh, stopChan, startTime, validVaultCount, &wg, *statsIntervalFlag)

	// start the processing logic
	startProc(*wordlistFileFlag, *outputFile, numThreads, stopChan, vaults, crackedCountCh, linesProcessedCh)

	// close stop channel to signal all workers to stop
	time.Sleep(10 * time.Millisecond)
	closeStopChannel(stopChan)
}

// end code
