// +build !pkcs11

package client

import (
	"fmt"
	"net/http"

	"github.com/docker/notary/passphrase"
	"github.com/docker/notary/trustmanager"
)

// NewNotaryRepository is a helper method that returns a new notary repository.
// It takes the base directory under where all the trust files will be stored
// (usually ~/.docker/trust/).
// However, if stateless is true, we will use a MemoryStore instead for the
// trust files.
func NewNotaryRepository(baseDir, gun, baseURL string, rt http.RoundTripper,
	retriever passphrase.Retriever, stateless bool) (
	*NotaryRepository, error) {

	var keyStore trustmanager.KeyStore
	if stateless {
		keyStore = trustmanager.NewKeyMemoryStore(retriever)
	} else {
		fileKeyStore, err := trustmanager.NewKeyFileStore(baseDir, retriever)
		if err != nil {
			return nil, fmt.Errorf("failed to create private key store in directory: %s", baseDir)
		}
		keyStore = fileKeyStore
	}

	return repositoryFromKeystores(baseDir, gun, baseURL, rt,
		[]trustmanager.KeyStore{keyStore}, stateless)
}
