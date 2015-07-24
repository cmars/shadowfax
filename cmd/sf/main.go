package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha512"
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"path/filepath"

	"github.com/boltdb/bolt"
	"github.com/howeyc/gopass"
	"golang.org/x/crypto/scrypt"
	"gopkg.in/alecthomas/kingpin.v2"
	"gopkg.in/errgo.v1"

	sf "github.com/cmars/shadowfax"
	sfhttp "github.com/cmars/shadowfax/http"
	"github.com/cmars/shadowfax/storage"
	sfbolt "github.com/cmars/shadowfax/storage/bolt"
)

var (
	urlFlagVar     **url.URL
	homedirFlagVar *string
	serverKeyFlag  = kingpin.Flag("server-key", "public key of shadowfax server").String()

	nameCmd = kingpin.Command("name", "contact names")

	nameAddCmd     = nameCmd.Command("add", "add name")
	nameAddNameArg = nameAddCmd.Arg("name", "contact name").String()
	nameAddAddrArg = nameAddCmd.Arg("addr", "contact address").String()

	nameListCmd = nameCmd.Command("list", "list names")

	addrCmd        = kingpin.Command("addr", "addresses")
	addrCreateCmd  = addrCmd.Command("create", "create new address")
	addrListCmd    = addrCmd.Command("list", "list addresses")
	addrDefaultCmd = addrCmd.Command("default", "show default address")

	msgCmd = kingpin.Command("msg", "messages")

	msgPushCmd       = msgCmd.Command("push", "push message")
	msgPushRcptArg   = msgPushCmd.Arg("recipient", "message recipient").String()
	msgPushSendFlag  = msgPushCmd.Flag("sender", "sender address").Short('s').String()
	msgPushInputFlag = msgPushCmd.Flag("file", "send file contents").Short('f').ExistingFile()

	msgPopCmd = msgCmd.Command("pop", "pop message")
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

	urlFlag := kingpin.Flag("url", "server URL").Short('u')
	defaultURL := os.Getenv("SHADOWFAX_SERVER")
	if defaultURL == "" {
		defaultURL = "https://localhost:8443"
	}
	urlFlagVar = urlFlag.Default(defaultURL).URL()
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

func nameList() error {
	contacts, err := newContacts()
	if err != nil {
		return err
	}
	cinfos, err := contacts.Current()
	if err != nil {
		return err
	}
	for _, cinfo := range cinfos {
		_, err = fmt.Printf("%-20s %-50s\n", cinfo.Name, cinfo.Address.Encode())
		if err != nil {
			return errgo.Mask(err)
		}
	}
	return nil
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
	if err != nil {
		return errgo.Mask(err)
	}

	contacts, err := newContacts()
	if err != nil {
		return err
	}
	err = contacts.Put("me", keyPair.PublicKey)
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
	salt, hash, err := getSaltHash(pass)
	if os.IsNotExist(errgo.Cause(err)) {
		// If the salt file isn't there, we need to confirm a new passphrase
		fmt.Print("Confirm: ")
		confirm := gopass.GetPasswd()
		if !bytes.Equal(confirm, pass) {
			return nil, errgo.New("passphrases did not match")
		}
		salt, err = createSaltHash(pass)
		if err != nil {
			return nil, errgo.Mask(err)
		}
	} else if err != nil {
		return nil, errgo.Mask(err)
	} else {
		checkHash := calcHash(pass, salt)
		if !bytes.Equal(hash, checkHash) {
			return nil, errgo.New("invalid passphrase")
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

const (
	vaultSaltName = "vault.salt"
	vaultSaltSize = 32
)

var hashVersion = []byte("v1")

func calcHash(pass, salt []byte) []byte {
	h := sha512.New384()
	h.Write(hashVersion)
	h.Write(salt)
	h.Write(pass)
	return h.Sum(nil)
}

func createSaltHash(pass []byte) ([]byte, error) {
	// generate a new salt
	salt := make([]byte, vaultSaltSize)
	_, err := rand.Reader.Read(salt)
	if err != nil {
		return nil, errgo.Mask(err)
	}

	saltPath := filepath.Join(*homedirFlagVar, vaultSaltName)
	f, err := os.OpenFile(saltPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	defer f.Close()

	_, err = f.Write(salt)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	_, err = f.Write(hashVersion)
	if err != nil {
		return nil, errgo.Mask(err)
	}

	newHash := calcHash(pass, salt)
	_, err = f.Write(newHash)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	return salt, nil
}

func getSaltHash(pass []byte) ([]byte, []byte, error) {
	saltPath := filepath.Join(*homedirFlagVar, vaultSaltName)
	saltHash, err := ioutil.ReadFile(saltPath)
	if err != nil {
		return nil, nil, errgo.Mask(err, errgo.Any)
	}
	if len(saltHash) < 32+2+sha512.Size384 {
		return nil, nil, errgo.New("invalid salt file")
	}
	return saltHash[:32], saltHash[34:], nil
}

func msgPush() error {
	vault, err := newVault()
	if err != nil {
		return errgo.Mask(err)
	}
	contacts, err := newContacts()
	if err != nil {
		return errgo.Mask(err)
	}

	var keyPair *sf.KeyPair
	if *msgPushSendFlag == "" {
		keyPair, err = vault.Current()
		if err != nil {
			return errgo.Mask(err)
		}
	} else {
		pk, err := sf.DecodePublicKey(*msgPushSendFlag)
		if err != nil {
			return errgo.Mask(err)
		}
		keyPair, err = vault.Get(pk)
		if err != nil {
			return errgo.Mask(err)
		}
	}

	rcptKey, err := contacts.Key(*msgPushRcptArg)
	if err != nil {
		return errgo.Mask(err)
	}

	var contents bytes.Buffer
	if *msgPushInputFlag == "" {
		_, err = io.Copy(&contents, os.Stdin)
		if err != nil {
			return errgo.Mask(err)
		}
	} else {
		f, err := os.Open(*msgPushInputFlag)
		if err != nil {
			return errgo.Mask(err)
		}
		_, err = io.Copy(&contents, f)
		f.Close()
		if err != nil {
			return errgo.Mask(err)
		}
	}

	client, err := newClient(keyPair)
	if err != nil {
		return errgo.Mask(err)
	}

	err = client.Push(rcptKey.Encode(), contents.Bytes())
	return errgo.Mask(err)
}

func newClient(keyPair *sf.KeyPair) (*sfhttp.Client, error) {
	var err error
	var serverKey *sf.PublicKey
	if *serverKeyFlag == "" {
		serverKey, err = sfhttp.PublicKey((*urlFlagVar).String(), nil)
		if err != nil {
			return nil, errgo.Mask(err)
		}
	} else {
		serverKey, err = sf.DecodePublicKey(*serverKeyFlag)
		if err != nil {
			return nil, errgo.Mask(err)
		}
	}

	return sfhttp.NewClient(*keyPair, (*urlFlagVar).String(), serverKey, &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}), nil
}

func msgPop() error {
	vault, err := newVault()
	if err != nil {
		return errgo.Mask(err)
	}
	keyPair, err := vault.Current()
	if err != nil {
		return errgo.Mask(err)
	}
	client, err := newClient(keyPair)
	if err != nil {
		return errgo.Mask(err)
	}
	msgs, err := client.Pop()
	if err != nil {
		return errgo.Mask(err)
	}
	for i, msg := range msgs {
		_, err = fmt.Println(i, msg.ID, msg.Sender, msg.Contents)
		if err != nil {
			return errgo.Mask(err)
		}
	}
	return nil
}

func notImplemented() error {
	return errgo.New("not implemented yet")
}

var (
	addrList = notImplemented
)
