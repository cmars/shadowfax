package main

import (
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/boltdb/bolt"
	"github.com/julienschmidt/httprouter"
	"gopkg.in/alecthomas/kingpin.v2"
	"gopkg.in/errgo.v1"
	"gopkg.in/tomb.v2"

	sf "github.com/cmars/shadowfax"
	sfhttp "github.com/cmars/shadowfax/http"
	boltstorage "github.com/cmars/shadowfax/storage/bolt"
)

var (
	httpFlag    = kingpin.Flag("http", "http port").Default(":8080").String()
	httpsFlag   = kingpin.Flag("https", "https port").String()
	certFlag    = kingpin.Flag("cert", "tls certificate").ExistingFile()
	keyFlag     = kingpin.Flag("key", "tls keyfile").ExistingFile()
	keypairFlag = kingpin.Flag("keypair", "curve25519 keypair file").Default("sfd.keypair").String()
	dbFileFlag  = kingpin.Flag("dbfile", "path to database file").Default("sfd.db").String()
)

var (
	osExit      = os.Exit
	boltOptions = bolt.Options{
		Timeout: 30 * time.Second,
	}
)

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
	kingpin.Parse()

	db, err := newDB()
	if err != nil {
		return errgo.Mask(err)
	}
	keyPair, err := loadKeyPair()
	if err != nil {
		return errgo.Mask(err)
	}
	service := boltstorage.NewService(db)
	handler := sfhttp.NewHandler(keyPair, service)

	r := httprouter.New()
	handler.Register(r)

	var t tomb.Tomb
	if *httpFlag != "" {
		t.Go(func() error {
			return http.ListenAndServe(*httpFlag, r)
		})
	}
	if *httpsFlag != "" && *certFlag != "" && *keyFlag != "" {
		t.Go(func() error {
			return http.ListenAndServeTLS(*httpsFlag, *certFlag, *keyFlag, r)
		})
	}

	log.Printf("public key: %s", keyPair.PublicKey.Encode())
	return t.Wait()
}

func newDB() (*bolt.DB, error) {
	db, err := bolt.Open(*dbFileFlag, 0600, &boltOptions)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	return db, nil
}

func loadKeyPair() (*sf.KeyPair, error) {
	f, err := os.Open(*keypairFlag)
	if os.IsNotExist(err) {
		return newKeyPair()
	} else if err != nil {
		return nil, errgo.Mask(err)
	}
	defer f.Close()

	var keyPair sf.KeyPair
	keyPair.PublicKey = new(sf.PublicKey)
	keyPair.PrivateKey = new(sf.PrivateKey)
	_, err = io.ReadFull(f, keyPair.PublicKey[:])
	if err != nil {
		return nil, errgo.Mask(err)
	}
	_, err = io.ReadFull(f, keyPair.PrivateKey[:])
	if err != nil {
		return nil, errgo.Mask(err)
	}
	return &keyPair, nil
}

func newKeyPair() (*sf.KeyPair, error) {
	f, err := os.OpenFile(*keypairFlag, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	defer f.Close()
	kp, err := sf.NewKeyPair()
	_, err = f.Write(kp.PublicKey[:])
	if err != nil {
		return nil, errgo.Mask(err)
	}
	_, err = f.Write(kp.PrivateKey[:])
	if err != nil {
		return nil, errgo.Mask(err)
	}
	return &kp, nil
}
