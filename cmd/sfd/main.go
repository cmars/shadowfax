package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/boltdb/bolt"
	"github.com/julienschmidt/httprouter"
	"gopkg.in/errgo.v1"
	"gopkg.in/tomb.v2"

	sf "github.com/cmars/shadowfax"
	sfhttp "github.com/cmars/shadowfax/http"
	boltstorage "github.com/cmars/shadowfax/storage/bolt"
)

type Config struct {
	HTTPPort       int    `json:"http-port"`
	HTTPSPort      int    `json:"https-port,omitempty"`
	TLSCertFile    string `json:"tls-cert-file,omitempty"`
	TLSKeyFile     string `json:"tls-key-file,omitempty"`
	PublicKey      string `json:"public-key"`
	PrivateKeyFile string `json:"private-key"`
	BoltDBFile     string `json:"bolt-db-file,omitempty"`
}

func (c *Config) loadKeyPair() (sf.KeyPair, error) {
	if c.PublicKey == "" {
		return sf.NewKeyPair()
	}
	var fail sf.KeyPair

	publicKey, err := sf.DecodePublicKey(c.PublicKey)
	if err != nil {
		return fail, errgo.Mask(err)
	}
	privateKey := new(sf.PrivateKey)
	buf, err := ioutil.ReadFile(c.PrivateKeyFile)
	if err != nil {
		return fail, errgo.Mask(err)
	}
	copy(privateKey[:], buf)
	return sf.KeyPair{PublicKey: publicKey, PrivateKey: privateKey}, nil
}

var (
	osExit        = os.Exit
	defaultConfig Config
	boltOptions   = bolt.Options{
		Timeout: 30 * time.Second,
	}
)

func init() {
	defaultConfig = Config{
		HTTPPort:   8080,
		BoltDBFile: "sfd.db",
	}
}

func die(err error) {
	if err != nil {
		log.Println(errgo.Details(err))
		osExit(1)
	}
	os.Exit(0)
}

func main() {
	err := run()
	die(err)
}

func run() error {
	config := defaultConfig
	boltDB, err := bolt.Open(config.BoltDBFile, 0600, &boltOptions)
	if err != nil {
		return errgo.Mask(err)
	}
	keyPair, err := config.loadKeyPair()
	if err != nil {
		return errgo.Mask(err)
	}
	service := boltstorage.NewService(boltDB)
	handler := sfhttp.NewHandler(keyPair, service)

	r := httprouter.New()
	handler.Register(r)

	var t tomb.Tomb
	if config.HTTPPort != 0 {
		t.Go(func() error {
			return http.ListenAndServe(fmt.Sprintf(":%d", config.HTTPPort), r)
		})
	}
	if config.HTTPSPort != 0 && config.TLSCertFile != "" && config.TLSKeyFile != "" {
		t.Go(func() error {
			return http.ListenAndServeTLS(fmt.Sprintf(":%d", config.HTTPSPort), config.TLSCertFile, config.TLSKeyFile, r)
		})
	}
	return t.Wait()
}
