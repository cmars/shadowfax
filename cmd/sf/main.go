package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"path/filepath"

	"github.com/boltdb/bolt"
	"github.com/howeyc/gopass"
	"golang.org/x/crypto/scrypt"
	"gopkg.in/alecthomas/kingpin.v2"
	"gopkg.in/errgo.v1"

	sf "github.com/cmars/shadowfax"
	"github.com/cmars/shadowfax/storage"
	sfbolt "github.com/cmars/shadowfax/storage/bolt"
)

var (
	urlFlag        = kingpin.Flag("url", "server URL").Default("http://localhost:8080").URL()
	homedirFlagVar *string

	nameCmd = kingpin.Command("name", "contact names")

	nameAddCmd     = nameCmd.Command("add", "add name")
	nameAddNameArg = nameAddCmd.Arg("name", "contact name").String()
	nameAddAddrArg = nameAddCmd.Arg("addr", "contact address").String()

	nameListCmd = nameCmd.Command("list", "list names")

	addrCmd        = kingpin.Command("addr", "addresses")
	addrCreateCmd  = addrCmd.Command("create", "create new address")
	addrListCmd    = addrCmd.Command("list", "list addresses")
	addrDefaultCmd = addrCmd.Command("default", "show default address")

	msgCmd     = kingpin.Command("msg", "messages")
	msgPushCmd = msgCmd.Command("push", "push message")
	msgPopCmd  = msgCmd.Command("pop", "pop message")
)

func init() {
	homedirFlag := kingpin.Flag("homedir", "shadowfax home directory")
	defaultHomeDir := os.Getenv("HOME")
	user, err := user.Current()
	if err != nil {
		defaultHomeDir = filepath.Join(os.Getenv("HOME"), ".shadowfax")
	} else {
		defaultHomeDir = filepath.Join(user.HomeDir, ".shadowfax")
	}
	homedirFlagVar = homedirFlag.Default(defaultHomeDir).String()
}

func main() {
	cmd := kingpin.Parse()

	err := os.MkdirAll(*homedirFlagVar, 0700)
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot create homedir %q: %v", *homedirFlagVar, err)
		os.Exit(1)
	}

	noSuchCmdErr := errgo.Newf("command not recognized: %q", cmd)
	err = noSuchCmdErr
	switch cmd {
	case "name add":
		err = nameAdd()
	case "name list":
		err = nameList()
	case "addr create":
		err = addrCreate()
	case "addr list":
		err = addrList()
	case "addr default":
		err = addrDefault()
	case "msg push":
		err = msgPush()
	case "msg pop":
		err = msgPop()
	}
	if err != nil {
		if err == noSuchCmdErr {
			kingpin.Usage()
		} else {
			fmt.Fprintln(os.Stderr, errgo.Details(err))
		}
		os.Exit(1)
	}
	os.Exit(0)
}

func nameAdd() error {
	contacts, err := newContacts()
	if err != nil {
		return err
	}
	addrPk, err := sf.DecodePublicKey(*nameAddAddrArg)
	if err != nil {
		return errgo.Mask(err)
	}
	err = contacts.Put(*nameAddNameArg, addrPk)
	return errgo.Mask(err)
}

func newContacts() (storage.Contacts, error) {
	contactsPath := filepath.Join(*homedirFlagVar, "contacts")
	db, err := bolt.Open(contactsPath, 0600, nil)
	if err != nil {
		return nil, errgo.WithCausef(nil, err, "cannot open contacts %q", contactsPath)
	}
	return sfbolt.NewContacts(db), nil
}

func addrCreate() error {
	vault, err := newVault()
	if err != nil {
		return errgo.Mask(err)
	}
	keyPair, err := sf.NewKeyPair()
	if err != nil {
		return errgo.Mask(err)
	}
	err = vault.Put(&keyPair)
	return errgo.Mask(err)
}

func addrDefault() error {
	vault, err := newVault()
	if err != nil {
		return errgo.Mask(err)
	}
	keyPair, err := vault.Current()
	if err != nil {
		return errgo.Mask(err)
	}
	_, err = fmt.Println(keyPair.PublicKey.Encode())
	return errgo.Mask(err)
}

func newVault() (storage.Vault, error) {
	sk, err := getVaultKey()
	if err != nil {
		return nil, errgo.Mask(err)
	}

	vaultPath := filepath.Join(*homedirFlagVar, "vault")
	db, err := bolt.Open(vaultPath, 0600, nil)
	if err != nil {
		return nil, errgo.WithCausef(nil, err, "cannot open vault %q", vaultPath)
	}
	return sfbolt.NewVault(db, sk), nil
}

func getVaultKey() (*sf.SecretKey, error) {
	fmt.Print("Passphrase: ")
	pass := gopass.GetPasswd()
	salt, isNew, err := getSalt(pass)
	if err != nil {
		return nil, errgo.Mask(err)
	}

	if isNew {
		fmt.Print("Confirm: ")
		confirm := gopass.GetPasswd()
		if !bytes.Equal(confirm, pass) {
			return nil, errgo.New("passphrases did not match")
		}
	}

	var sk sf.SecretKey
	derived, err := scrypt.Key(pass, salt, 16384, 8, 1, 32)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	copy(sk[:], derived)
	return &sk, nil
}

func getSalt(pass []byte) ([]byte, bool, error) {
	saltPath := filepath.Join(*homedirFlagVar, "vault.salt")
	salt, err := ioutil.ReadFile(saltPath)
	if os.IsNotExist(err) {
		// generate a new salt
		salt = make([]byte, 256)
		_, err = rand.Reader.Read(salt)
		if err != nil {
			return nil, false, errgo.Mask(err)
		}
		err = ioutil.WriteFile(saltPath, salt, 0600)
		if err != nil {
			return nil, false, errgo.Mask(err)
		}
	}

	h := sha512.New384()
	h.Write([]byte("v1,"))
	h.Write(salt)
	h.Write(pass)
	sum := h.Sum(nil)

	var isNew bool
	hashPath := filepath.Join(*homedirFlagVar, "vault.hash")
	hashPrev, err := ioutil.ReadFile(hashPath)
	if os.IsNotExist(err) {
		err = ioutil.WriteFile(hashPath, sum, 0600)
		if err != nil {
			return nil, false, errgo.Mask(err)
		}
		isNew = true
	} else if !bytes.Equal(hashPrev, sum) {
		return nil, false, errgo.New("invalid passphrase")
	}

	return salt, isNew, nil
}

func notImplemented() error {
	return errgo.New("not implemented yet")
}

var (
	nameList = notImplemented
	addrList = notImplemented
	msgPush  = notImplemented
	msgPop   = notImplemented
)
