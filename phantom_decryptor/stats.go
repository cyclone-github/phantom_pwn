package main

import (
	"fmt"
	"log"
	"os"
	"sync"
	"time"
)

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
