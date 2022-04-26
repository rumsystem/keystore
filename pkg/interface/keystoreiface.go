package cypto

type KeyPair struct {
	PublicKey  string
	PrivateKey string
}

type CyptoIface interface {
	CreateKeyPair() (key KeyPair, err error)
	ImportKey(privateKey string) (publicKey string, err error)
	ListAll() (keys []KeyPair, err error)
	Sign(data []byte, pubKey string) (signature []byte, err error)
	Verify(data []byte, pubkey string) (verified bool, err error)
}
