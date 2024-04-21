package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/btcsuite/btcutil/base58"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/pbkdf2"
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
	fmt.Fprintln(os.Stderr, "Cyclone's Phantom Vault Decryptor v0.1.0-2024-04-20-2000\nhttps://github.com/cyclone-github/phantom_pwn\n")
}

// help func
func helpFunc() {
	versionFunc()
	str := `Example Usage:

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

./phantom_decryptor.bin -h phantom.txt -w wordlist.txt -o output.txt`
	fmt.Fprintln(os.Stderr, str)
}

// PhantomVault struct
type PhantomVault struct {
	EncryptedData []byte
	Salt          []byte
	Nonce         []byte
	Iterations    int
	Decrypted     bool
}

// dehex wordlist line
/* note:
the checkForHexBytes() function below gives a best effort in decoding all HEX strings and applies error correction when needed
if your wordlist contains HEX strings that resemble alphabet soup, don't be surprised if you find "garbage in" still means "garbage out"
the best way to fix HEX decoding issues is to correctly parse your wordlists so you don't end up with foobar HEX strings
if you have suggestions on how to better handle HEX decoding errors, contact me on github
*/
func checkForHexBytes(line []byte) ([]byte, []byte, int) {
	hexPrefix := []byte("$HEX[")
	suffix := byte(']')

	// Step 1: Check for prefix and adjust for missing ']'
	if bytes.HasPrefix(line, hexPrefix) {
		var hexErrorDetected int
		if line[len(line)-1] != suffix {
			line = append(line, suffix) // Correcting the malformed $HEX[]
			hexErrorDetected = 1
		}

		// Step 2: Find the indices for the content inside the brackets
		startIdx := bytes.IndexByte(line, '[')
		endIdx := bytes.LastIndexByte(line, ']')
		if startIdx == -1 || endIdx == -1 || endIdx <= startIdx {
			return line, line, 1 // Early return on malformed bracket positioning
		}
		hexContent := line[startIdx+1 : endIdx]

		// Step 3 & 4: Decode the hex content and handle errors by cleaning if necessary
		decodedBytes := make([]byte, hex.DecodedLen(len(hexContent)))
		n, err := hex.Decode(decodedBytes, hexContent)
		if err != nil {
			// Clean the hex content: remove invalid characters and ensure even length
			cleaned := make([]byte, 0, len(hexContent))
			for _, b := range hexContent {
				if ('0' <= b && b <= '9') || ('a' <= b && b <= 'f') || ('A' <= b && b <= 'F') {
					cleaned = append(cleaned, b)
				}
			}
			if len(cleaned)%2 != 0 {
				cleaned = append([]byte{'0'}, cleaned...) // Ensuring even number of characters
			}

			decodedBytes = make([]byte, hex.DecodedLen(len(cleaned)))
			_, err = hex.Decode(decodedBytes, cleaned)
			if err != nil {
				return line, line, 1 // Return original if still failing
			}
			hexErrorDetected = 1
		}
		decodedBytes = decodedBytes[:n] // Trim the slice to the actual decoded length
		return decodedBytes, hexContent, hexErrorDetected
	}
	// Step 5: Return original if not a hex string
	return line, line, 0
}

// hash cracking worker
func startCracker(stopChan chan struct{}, password []byte, vaults []PhantomVault, crackedCountCh chan int, linesProcessedCh chan int) {
	allDecrypted := true

	for i := range vaults {
		if !vaults[i].Decrypted { // check only undecrypted vaults
			decryptedData, err := decryptVault(vaults[i].EncryptedData, password, vaults[i].Salt, vaults[i].Nonce, vaults[i].Iterations)
			if err != nil {
				allDecrypted = false
				continue // skip to next vault if decryption fails
			}
			if isValid(decryptedData) {
				crackedCountCh <- 1
				vaults[i].Decrypted = true
				//fmt.Printf("\nPassword: '%s'\nHEX Seed: `%x`\n", password, string(decryptedData)) // HEX seed generation not yet working
				fmt.Printf("\nPassword: '%s'\n", password)
			} else {
				allDecrypted = false
			}
		}
	}

	linesProcessedCh <- 1

	if allDecrypted {
		closeStopChannel(stopChan)
	}
}

func closeStopChannel(stopChan chan struct{}) {
	select {
	case <-stopChan:
		// channel already closed, do nothing
	default:
		close(stopChan)
	}
}

// process wordlist chunks
func processChunk(chunk []byte, count *int64, hexErrorCount *int64, writer *bufio.Writer, stopChan chan struct{}, vaults []PhantomVault, crackedCountCh chan int, linesProcessedCh chan int) {
	lineStart := 0
	for i := 0; i < len(chunk); i++ {
		if chunk[i] == '\n' {
			password := chunk[lineStart:i]
			decodedBytes, _, hexErrCount := checkForHexBytes(password)
			startCracker(stopChan, decodedBytes, vaults, crackedCountCh, linesProcessedCh)
			atomic.AddInt64(count, 1)
			atomic.AddInt64(hexErrorCount, int64(hexErrCount))
			lineStart = i + 1 // move start index past the newline
		}
	}

	// handle cases where there is no newline at the end of the chunk
	if lineStart < len(chunk) {
		password := chunk[lineStart:]
		decodedBytes, _, hexErrCount := checkForHexBytes(password)
		startCracker(stopChan, decodedBytes, vaults, crackedCountCh, linesProcessedCh)
		atomic.AddInt64(count, 1)
		atomic.AddInt64(hexErrorCount, int64(hexErrCount))
	}

	writer.Flush()
}

// process logic
func startProc(wordlistFileFlag string, outputPath string, numGoroutines int, stopChan chan struct{}, vaults []PhantomVault, crackedCountCh chan int, linesProcessedCh chan int) {
	const readBufferSize = 1024 * 1024 // read buffer
	const writeBufferSize = 128 * 1024 // write buffer

	var linesHashed int64 = 0
	var procWg sync.WaitGroup
	var readWg sync.WaitGroup
	var writeWg sync.WaitGroup
	var hexDecodeErrors int64 = 0 // hex error counter

	readChunks := make(chan []byte, 500) // channel for reading chunks of data
	writeData := make(chan []byte, 10)   // channel for writing processed data

	var file *os.File
	var err error
	if wordlistFileFlag == "" {
		file = os.Stdin // default to stdin if no input flag is provided
	} else {
		file, err = os.Open(wordlistFileFlag)
		if err != nil {
			log.Printf("Error opening file: %v\n", err)
			return
		}
		defer file.Close()
	}

	startTime := time.Now()

	readWg.Add(1)
	go func() {
		defer readWg.Done()
		var remainder []byte
		reader := bufio.NewReaderSize(file, readBufferSize)
		for {
			chunk := make([]byte, readBufferSize)
			n, err := reader.Read(chunk)
			if err == io.EOF {
				break
			}
			if err != nil {
				fmt.Println(os.Stderr, "Error reading chunk:", err)
				return
			}

			chunk = chunk[:n]
			chunk = append(remainder, chunk...)

			lastNewline := bytes.LastIndexByte(chunk, '\n')
			if lastNewline == -1 {
				remainder = chunk
			} else {
				readChunks <- chunk[:lastNewline+1]
				remainder = chunk[lastNewline+1:]
			}
		}
		if len(remainder) > 0 {
			readChunks <- remainder
		}
		close(readChunks)
	}()

	for i := 0; i < numGoroutines; i++ {
		procWg.Add(1)
		go func() {
			defer procWg.Done()
			for chunk := range readChunks {
				localBuffer := bytes.NewBuffer(nil)
				writer := bufio.NewWriterSize(localBuffer, writeBufferSize)
				processChunk(chunk, &linesHashed, &hexDecodeErrors, writer, stopChan, vaults, crackedCountCh, linesProcessedCh)
				writer.Flush()
				if localBuffer.Len() > 0 {
					writeData <- localBuffer.Bytes()
				}
			}
		}()
	}

	writeWg.Add(1)
	go func() {
		defer writeWg.Done()
		var writer *bufio.Writer
		if outputPath != "" {
			outFile, err := os.Create(outputPath)
			if err != nil {
				fmt.Println(os.Stderr, "Error creating output file:", err)
				return
			}
			defer outFile.Close()
			writer = bufio.NewWriterSize(outFile, writeBufferSize)
		} else {
			writer = bufio.NewWriterSize(os.Stdout, writeBufferSize)
		}

		for data := range writeData {
			writer.Write(data)
		}
		writer.Flush()
	}()

	procWg.Wait()
	readWg.Wait()
	close(writeData)
	writeWg.Wait()

	elapsedTime := time.Since(startTime)
	runTime := float64(elapsedTime.Seconds())
	linesPerSecond := float64(linesHashed) / elapsedTime.Seconds()
	if hexDecodeErrors > 0 {
		log.Printf("HEX decode errors: %d\n", hexDecodeErrors)
	}
	log.Printf("Finished processing %d lines in %.3f sec (%.3f lines/sec)\n", linesHashed, runTime, linesPerSecond)
}

// decryptVault using secretbox
func decryptVault(encryptedData, password, salt, nonce []byte, iterations int) ([]byte, error) {
	if len(nonce) != 24 {
		return nil, fmt.Errorf("nonce must be exactly 24 bytes long")
	}

	key := pbkdf2.Key(password, salt, iterations, 32, sha256.New)

	var nonceArray [24]byte
	copy(nonceArray[:], nonce)
	var keyArray [32]byte
	copy(keyArray[:], key)

	decrypted, ok := secretbox.Open(nil, encryptedData, &nonceArray, &keyArray)
	if !ok {
		return nil, fmt.Errorf("decryption failed")
	}

	return decrypted, nil
}

// isValid function as placeholder, always returning true
func isValid(s []byte) bool {
	return true
}

// parse Phantom vault
func readPhantomData(filePath string) ([]PhantomVault, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var vaults []PhantomVault
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		var hash struct {
			EncryptedKey struct {
				Digest     string `json:"digest"`
				Encrypted  string `json:"encrypted"`
				Salt       string `json:"salt"`
				Nonce      string `json:"nonce"`
				Iterations int    `json:"iterations"`
				Kdf        string `json:"kdf"`
			} `json:"encryptedKey"`
		}

		line := scanner.Text()
		if err := json.Unmarshal([]byte(line), &hash); err != nil {
			log.Printf("Error parsing JSON: %v\n", err)
			continue
		}

		// sanity checks for Phanton vault
		if hash.EncryptedKey.Digest != "sha256" ||
			hash.EncryptedKey.Kdf != "pbkdf2" ||
			hash.EncryptedKey.Iterations <= 0 ||
			len(hash.EncryptedKey.Encrypted) == 0 ||
			len(hash.EncryptedKey.Salt) == 0 ||
			len(hash.EncryptedKey.Nonce) == 0 {
			log.Printf("Invalid or incomplete data encountered in JSON: %v\n", line)
			continue
		}

		encryptedData := base58.Decode(hash.EncryptedKey.Encrypted)
		salt := base58.Decode(hash.EncryptedKey.Salt)
		nonce := base58.Decode(hash.EncryptedKey.Nonce)

		if len(encryptedData) == 0 || len(salt) == 0 || len(nonce) == 0 {
			log.Printf("Error decoding base58 data: possibly incorrect format or content: %v\n", line)
			continue
		}

		vault := PhantomVault{
			EncryptedData: encryptedData,
			Salt:          salt,
			Nonce:         nonce,
			Iterations:    hash.EncryptedKey.Iterations,
		}
		vaults = append(vaults, vault)
	}

	return vaults, nil
}

// monitor status
func monitorPrintStats(crackedCountCh, linesProcessedCh <-chan int, stopChan <-chan struct{}, startTime time.Time, validVaultCount int, wg *sync.WaitGroup, interval int) {
	crackedCount := 0
	linesProcessed := 0
	var ticker *time.Ticker
	if interval > 0 {
		ticker = time.NewTicker(time.Duration(interval) * time.Second)
		defer ticker.Stop()
	}

	for {
		select {
		case <-crackedCountCh:
			crackedCount++
		case <-linesProcessedCh:
			linesProcessed++
		case <-stopChan:
			// print final stats and exit
			printStats(time.Since(startTime), crackedCount, validVaultCount, linesProcessed, true)
			wg.Done()
			return
		case <-func() <-chan time.Time {
			if ticker != nil {
				return ticker.C
			}
			// return nil channel if ticker is not used
			return nil
		}():
			if interval > 0 {
				printStats(time.Since(startTime), crackedCount, validVaultCount, linesProcessed, false)
			}
		}
	}
}

// printStats
func printStats(elapsedTime time.Duration, crackedCount, validVaultCount, linesProcessed int, exitProgram bool) {
	hours := int(elapsedTime.Hours())
	minutes := int(elapsedTime.Minutes()) % 60
	seconds := int(elapsedTime.Seconds()) % 60
	linesPerSecond := float64(linesProcessed) / elapsedTime.Seconds()
	log.Printf("Decrypted: %d/%d %.2f h/s %02dh:%02dm:%02ds", crackedCount, validVaultCount, linesPerSecond, hours, minutes, seconds)
	if exitProgram {
		fmt.Println("")
		time.Sleep(100 * time.Millisecond)
		os.Exit(0) // exit only if indicated by 'exitProgram' flag
	}
}

// goroutine to watch for ctrl+c
func handleGracefulShutdown(stopChan chan struct{}) {
	interruptChan := make(chan os.Signal, 1)
	signal.Notify(interruptChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-interruptChan
		fmt.Fprintln(os.Stderr, "\nCtrl+C pressed. Shutting down...")
		//close(stopChan)
		closeStopChannel(stopChan)
	}()
}

// set CPU threads
func setNumThreads(userThreads int) int {
	if userThreads <= 0 || userThreads > runtime.NumCPU() {
		return runtime.NumCPU()
	}
	return userThreads
}

// print welcome screen
func printWelcomeScreen(vaultFileFlag, wordlistFileFlag *string, validVaultCount, numThreads int) {
	fmt.Fprintln(os.Stderr, " ----------------------------------------------- ")
	fmt.Fprintln(os.Stderr, "|       Cyclone's Phantom Vault Decryptor       |")
	fmt.Fprintln(os.Stderr, "| https://github.com/cyclone-github/phantom_pwn |")
	fmt.Fprintln(os.Stderr, " ----------------------------------------------- ")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "Vault file:\t%s\n", *vaultFileFlag)
	fmt.Fprintf(os.Stderr, "Valid Vaults:\t%d\n", validVaultCount)
	fmt.Fprintf(os.Stderr, "CPU Threads:\t%d\n", numThreads)

	// assume "stdin" if wordlistFileFlag is ""
	if *wordlistFileFlag == "" {
		fmt.Fprintf(os.Stderr, "Wordlist:\tReading stdin\n")
	} else {
		fmt.Fprintf(os.Stderr, "Wordlist:\t%s\n", *wordlistFileFlag)
	}

	//fmt.Fprintln(os.Stderr, "Working...")
	log.Println("Working...")
}

// main func
func main() {
	wordlistFileFlag := flag.String("w", "", "Input file to process (omit -w to read from stdin)")
	vaultFileFlag := flag.String("h", "", "Phantom Vault File")
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
	vaults, err := readPhantomData(*vaultFileFlag)
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
