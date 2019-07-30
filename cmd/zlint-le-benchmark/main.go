package main

import (
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint"
)

func loadCert(filename string) *x509.Certificate {
	certPEM, err := ioutil.ReadFile(filename)
	if err != nil {
		panic(fmt.Sprintf("error reading certfile %q: %v\n", filename, err))
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		panic(fmt.Sprintf("no cert PEM block in %q\n", filename))
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic(fmt.Sprintf("error parsing PEM block in %q: %v\n", filename, err))
	}
	return cert
}

func main() {
	if len(os.Args) != 2 {
		fmt.Printf("Usage: %s <PEM encoded certificate file path>\n", os.Args[0])
		os.Exit(1)
	}

	testDuration := time.Minute

	certFile := os.Args[1]
	c := loadCert(certFile)
	tick := time.NewTicker(time.Second)
	quit := make(chan bool, 2)
	testEnd := time.After(testDuration)

	fmt.Printf("Starting to lint %q over and over for %s. "+
		"Hit ctrl-c to end early.\n",
		certFile,
		testDuration)

	var iterations int32
	var count int32
	var lintsPerformed int32

	go func() {
		for {
			select {
			case <-quit:
				return
			default:
				_ = zlint.LintCertificate(c)
				atomic.AddInt32(&count, 1)
			}
		}
	}()

	go func() {
		for {
			select {
			case <-quit:
				tick.Stop()
				fmt.Printf("\n")
				return
			case <-tick.C:
				linted := atomic.LoadInt32(&count)
				atomic.StoreInt32(&count, 0)
				atomic.AddInt32(&lintsPerformed, linted)
				atomic.AddInt32(&iterations, 1)
				fmt.Printf(".")
			}
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM)
	signal.Notify(sigChan, syscall.SIGINT)
	signal.Notify(sigChan, syscall.SIGHUP)

	select {
	case <-sigChan:
		quit <- true
		quit <- true
	case <-testEnd:
		quit <- true
		quit <- true
	}

	lintsPerSecond := lintsPerformed / iterations
	fmt.Printf("\n\nPerformed an average of %d lints per second\n", lintsPerSecond)
	fmt.Printf("Total lints: %d Duration: %s\n", lintsPerformed, time.Duration(iterations)*time.Second)
}
