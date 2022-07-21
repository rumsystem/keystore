//go:build js && wasm
// +build js,wasm

package crypto

import (
	"testing"
)

func TestEthSign(t *testing.T) {
	password := "my.Passw0rd"
	ks, err := InitBrowserKeystore(password)
	if err != nil {
		t.Errorf("keystore init err: %s", err)
	}

	FactoryTestEthSign(ks, password, func(k Keystore, name string) (interface{}, error) {
		return k.(*BrowserKeystore).GetUnlockedKey(name)
	})(t)
}
