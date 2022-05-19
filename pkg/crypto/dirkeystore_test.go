package crypto

import (
	"fmt"
	"log"
	"testing"

	ethkeystore "github.com/ethereum/go-ethereum/accounts/keystore"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/rumsystem/keystore/pkg/options"
)

func TestInitDirKeyStore(t *testing.T) {
	name := "testkeystore"
	tempdir := fmt.Sprintf("%s/%s", t.TempDir(), name)
	log.Printf("tempdir %s", tempdir)
	_, count, err := InitDirKeyStore(name, tempdir)
	if err != nil {
		t.Errorf("keystore init err: %s", err)
	}
	if count != 0 {
		t.Errorf("init new keystore count should be 0, not : %d", count)
	}
}

func TestNewSignKey(t *testing.T) {
	name := "testnewkey"
	password := "my.Passw0rd"
	tempdir := fmt.Sprintf("%s/%s", t.TempDir(), name)
	dirks, _, err := InitDirKeyStore(name, tempdir)
	if err != nil {
		t.Errorf("keystore init err: %s", err)
	}
	key1name := "key1"
	newsignaddr, err := dirks.NewKey(key1name, Sign, password)
	keyname := Sign.NameString(key1name)
	key, err := dirks.GetKeyFromUnlocked(keyname)
	if err != nil {
		t.Errorf("Get Unlocked key err: %s", err)
	}
	ethkey, ok := key.(*ethkeystore.Key)
	if ok == false {
		t.Errorf("new key is not a eth sign key: %s", key)
	}
	pubaddress := ethcrypto.PubkeyToAddress(ethkey.PrivateKey.PublicKey).Hex()
	if pubaddress != newsignaddr {
		t.Errorf("new key address is not matched %s / %s", pubaddress, newsignaddr)
	}

	signature, err := dirks.SignByKeyName(key1name, []byte("a test string"))
	if err != nil {
		t.Errorf("Signnature err: %s", err)
	}

	//should succ
	result, err := dirks.VerifySignByKeyName(key1name, []byte("a test string"), signature)
	if err != nil {
		t.Errorf("Verify signnature err: %s", err)
	}

	if result == false {
		t.Errorf("signnature verify should successded but failed.")
	}

	//should fail
	result, err = dirks.VerifySignByKeyName(key1name, []byte("a new string"), signature)
	if err != nil {
		t.Errorf("Verify signnature err: %s", err)
	}

	if result == true {
		t.Errorf("signnature verify should failed, but it succeeded.")
	}
}

func TestImportSignKey(t *testing.T) {
	name := "testnewkey"
	tempdir := fmt.Sprintf("%s/%s", t.TempDir(), name)
	log.Printf("tempdir %s", tempdir)
	dirks, _, err := InitDirKeyStore(name, tempdir)
	if err != nil {
		t.Errorf("keystore init err: %s", err)
	}
	key1name := "key1"
	key1addr := "0x57c8CBB7966AAC85b32cB6827C0c14A4ae4Af0CE"
	address, err := dirks.Import(key1name, "84f8da8f95760fa3d0b6632ef66b89ea255a85974eccad7642ef12c4265677e0", Sign, "a.Passw0rda")
	if err != nil {
		t.Errorf("Get Unlocked key err: %s", err)
	}
	if address != key1addr {
		t.Errorf("key import is not matched: %s / %s ", address, key1addr)
	}
}

func TestNewEncryptKey(t *testing.T) {
	name := "testnewkey"
	password := "my.Passw0rd"
	tempdir := fmt.Sprintf("%s/%s", t.TempDir(), name)
	dirks, _, err := InitDirKeyStore(name, tempdir)
	if err != nil {
		t.Errorf("keystore init err: %s", err)
	}
	key1name := "key1"
	newencryptid, err := dirks.NewKey(key1name, Encrypt, password)
	if err != nil {
		t.Errorf("New encrypt key err : %s", err)
	}
	data := "secret message"
	encryptdata, err := dirks.EncryptTo([]string{newencryptid}, []byte(data))
	if err != nil {
		t.Errorf("encrypt data error : %s", err)
	}

	decrypteddata, err := dirks.Decrypt(key1name, encryptdata)
	if err != nil {
		t.Errorf("decrypt data error : %s", err)
	}
	if string(decrypteddata) != data {
		t.Errorf("decrypt data is not matched with orginal: %s / %s",
			string(decrypteddata), data)
	}
}

func TestMappingKey(t *testing.T) {

	nodeoptions, err := options.InitNodeOptions(t.TempDir(), "testpeername")

	name := "testnewkey"
	password := "my.Passw0rd"
	tempdir := fmt.Sprintf("%s/%s", t.TempDir(), name)
	t.Log(tempdir)
	dirks, _, err := InitDirKeyStore(name, tempdir)
	if err != nil {
		t.Errorf("keystore init err: %s", err)
	}

	//unlock keymap
	err = dirks.Unlock(nodeoptions.SignKeyMap, password)

	mappingkeyname := ""
	mappingkeyname1 := ""
	//create 6 keyparis, and mapping the fourth keypair to a new keyname
	for i := 0; i < 6; i++ {
		keyname := fmt.Sprintf("key%d", i)
		newsignid, err := dirks.NewKey(keyname, Sign, password)
		if err != nil {
			t.Errorf("New encrypt key err : %s", err)
		}
		//err = nodeoptions.SetSignKeyMap(keyname, newsignid)

		t.Logf("new signkey: %s", newsignid)
		_, err = dirks.NewKey(keyname, Encrypt, password)
		if err != nil {
			t.Errorf("New encrypt key err : %s", err)
		}
		if i == 1 {
			mappingkeyname = keyname
		} else if i == 3 {
			mappingkeyname1 = keyname
		}
	}
	t.Log("set keyalias...")
	aliasname := "a_new_mapping_keyname"
	err = dirks.NewAlias(aliasname, mappingkeyname, password)
	if err != nil {
		t.Errorf("new keyalias err...%s", err)
	}

	aliasname2 := "a_new_mapping_keyname_2"
	err = dirks.NewAlias(aliasname2, mappingkeyname, password)
	if err != nil {
		t.Errorf("new keyalias2 err...%s", err)
	}

	aliasname3 := "a_new_mapping_keyname_3"
	err = dirks.NewAlias(aliasname3, mappingkeyname1, password)
	if err != nil {
		t.Errorf("new keyalias3 err...%s", err)
	}

	keyname := dirks.AliasToKeyname(aliasname)
	if keyname == mappingkeyname {
		t.Logf("alias %s is keyname %s", aliasname, keyname)
	} else {
		t.Errorf("get alias %s err, can't find this alias", keyname)
	}

	err = dirks.NewAlias(aliasname, mappingkeyname, password)
	if err == nil {
		t.Errorf("repeat new keyalias should be failed")
	}

	t.Log("try unalias...")
	err = dirks.UnAlias(aliasname, password)
	if err != nil {
		t.Errorf("UnAlias err: %s", err)
	}
	t.Log("OK")
	t.Log("try unalias again...")

	err = dirks.UnAlias(aliasname, password)
	if err == nil {
		t.Errorf("repeat unalias should be failed")
	}
	t.Log("OK")

	t.Log("try unalias not exist alias...")
	err = dirks.UnAlias("not_exist_alias", password)
	if err == nil {
		t.Errorf("unalias not exist alias should be failed")
	}
	t.Log("OK")

	t.Log("try get encoded pubkey by alias...")
	pubkeybyalias, getkeyerr := dirks.GetEncodedPubkeyByAlias(aliasname3, Sign)
	if getkeyerr != nil {
		t.Errorf("GetEncodedPubkeyByAlias with alias %s err: %s", aliasname3, getkeyerr)
	}

	pubkeybyname, getkeyerr := dirks.GetEncodedPubkey(mappingkeyname1, Sign)
	if getkeyerr != nil {
		t.Errorf("GetEncodedPubkeyByAlias with name %s err: %s", pubkeybyname, getkeyerr)
	}

	_, getencryptkeyerr := dirks.GetEncodedPubkey(mappingkeyname1, Encrypt)
	if getencryptkeyerr != nil {
		t.Errorf("GetEncodedPubkeyByAlias Encrypt with name %s err: %s", pubkeybyname, getkeyerr)
	}

	if pubkeybyalias != pubkeybyname {
		t.Errorf("GetEncodedPubkey ByAlias or ByName should be equal.")
	}
	aliaslist := dirks.GetAlias(mappingkeyname1)
	if len(aliaslist) != 1 {
		t.Errorf("GetAlias of %s err", mappingkeyname1)
	}

	t.Log("try sign by alias...")
	testdata := "some random text for testing"
	testdatahash := Hash([]byte(testdata))
	signbyaliasresult, signerr := dirks.SignByKeyAlias(aliasname3, testdatahash)
	if signerr != nil {
		t.Errorf("SignByKeyAlias with alias %s err: %s", aliasname3, signerr)
	}

	verifyresult, verifyerr := dirks.VerifySignByKeyName(mappingkeyname1, testdatahash, signbyaliasresult)
	if verifyresult == false {
		t.Errorf("SignByKeyAlias %s verify err: %s", aliasname3, verifyerr)
	}

	verifyresult, _ = dirks.VerifySignByKeyName(mappingkeyname, testdatahash, signbyaliasresult)
	if verifyresult == true {
		t.Errorf("SignByKeyAlias %s verify by %s should be failed", aliasname3, mappingkeyname)
	}
	t.Log("OK")
}
