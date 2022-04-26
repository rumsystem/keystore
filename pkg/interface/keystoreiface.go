package cypto

type KeyPair struct {
	PublicKey  string
	PrivateKey string
}

type CyptoIface interface {
	CreateKeyPairWithKeyName(keyname string) (pubkey string, err error)
	RemoveKeyPairByKeyName(keyname string) (err error)
	GetKeyByKeyName(keyname string) (keypair KeyPair, err error)
	SignByKeyName(data []byte, keyname string) (signature []byte, err error)
	VeifyByKeyName(data []byte, keyname string) (verified bool, err error)

	CreateKeyPair() (key KeyPair, err error)
	ImportKey(privateKey string, keyname string) (publicKey string, err error)
	RemoveKey(publicKey string) (err error)
	ListAll() (keys []KeyPair, err error)
	Sign(data []byte, pubKey string) (signature []byte, err error)
	Verify(data []byte, pubkey string) (verified bool, err error)
}
