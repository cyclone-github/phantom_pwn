package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"
)

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

func closeStopChannel(stopChan chan struct{}) {
	select {
	case <-stopChan:
		// channel already closed, do nothing
	default:
		close(stopChan)
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
