package main

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"

	"github.com/boltdb/bolt"
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

	addrCmd       = kingpin.Command("addr", "addresses")
	addrCreateCmd = addrCmd.Command("create", "create new address")
	addrListCmd   = addrCmd.Command("list", "list addresses")

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

func notImplemented() error {
	return errgo.New("not implemented yet")
}

var (
	nameList   = notImplemented
	addrCreate = notImplemented
	addrList   = notImplemented
	msgPush    = notImplemented
	msgPop     = notImplemented
)
