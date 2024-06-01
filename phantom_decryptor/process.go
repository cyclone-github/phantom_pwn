package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// process logic
func startProc(wordlistFileFlag string, outputPath string, numGoroutines int, stopChan chan struct{}, vaults []Vault, crackedCountCh chan int, linesProcessedCh chan int) {
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

// process wordlist chunks
func processChunk(chunk []byte, count *int64, hexErrorCount *int64, writer *bufio.Writer, stopChan chan struct{}, vaults []Vault, crackedCountCh chan int, linesProcessedCh chan int) {
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

// hash cracking worker
func startCracker(stopChan chan struct{}, password []byte, vaults []Vault, crackedCountCh chan int, linesProcessedCh chan int) {
	allDecrypted := true

	for i := range vaults {
		if !vaults[i].Decrypted { // check only undecrypted vaults
			decryptedData, err := decryptVault(vaults[i].EncryptedData, password, vaults[i].Salt, vaults[i].Nonce, vaults[i].Iterations, vaults[i].Kdf)
			if err != nil {
				allDecrypted = false
				continue // skip to next vault if decryption fails
			}
			if isValid(decryptedData) {
				crackedCountCh <- 1
				vaults[i].Decrypted = true
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
