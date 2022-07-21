//go:build js && wasm
// +build js,wasm

package crypto

import (
	"testing"

	ethkeystore "github.com/ethereum/go-ethereum/accounts/keystore"
)

func TestEthSign(t *testing.T) {
	password := "my.Passw0rd"

	ks, err := InitBrowserKeystore(password)
	if err != nil {
		t.Errorf("keystore init err: %s", err)
	}
	bks := ks.(*BrowserKeystore)
	key1name := "key1"
	_, err = bks.NewKey(key1name, Sign, password)
	keyname := Sign.NameString(key1name)
	key, err := bks.GetUnlockedKey(keyname)
	if err != nil {
		t.Errorf("Get Unlocked key err: %s", err)
	}
	ethkey, ok := key.(*ethkeystore.Key)
	if ok == false {
		t.Errorf("new key is not a eth sign key: %s", key)
	}

	testdata := "some random text for testing"
	testdatahash := Hash([]byte(testdata))
	sig, err := bks.EthSign(testdatahash, ethkey.PrivateKey)
	if err != nil {
		t.Errorf("new key is not a eth sign key: %s", err)
	}
	verifyresult := bks.EthVerifySign(testdatahash, sig, &ethkey.PrivateKey.PublicKey)
	if verifyresult == false {
		t.Errorf("sig verify failure")
	}
}
