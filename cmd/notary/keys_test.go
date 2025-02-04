package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"golang.org/x/net/context"

	"github.com/Sirupsen/logrus"
	ctxu "github.com/docker/distribution/context"
	"github.com/docker/notary"
	"github.com/docker/notary/client"
	"github.com/docker/notary/cryptoservice"
	"github.com/docker/notary/passphrase"
	"github.com/docker/notary/server"
	"github.com/docker/notary/server/storage"
	"github.com/docker/notary/trustmanager"
	"github.com/docker/notary/tuf/data"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

var ret = passphrase.ConstantRetriever("pass")

// If there are no keys, removeKeyInteractively will just return an error about
// there not being any key
func TestRemoveIfNoKey(t *testing.T) {
	setUp(t)
	var buf bytes.Buffer
	stores := []trustmanager.KeyStore{trustmanager.NewKeyMemoryStore(nil)}
	err := removeKeyInteractively(stores, "12345", &buf, &buf)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "No key with ID")
}

// If there is one key, asking to remove it will ask for confirmation.  Passing
// anything other than 'yes'/'y'/'' response will abort the deletion and
// not delete the key.
func TestRemoveOneKeyAbort(t *testing.T) {
	setUp(t)
	nos := []string{"no", "NO", "AAAARGH", "   N    "}
	store := trustmanager.NewKeyMemoryStore(ret)

	key, err := trustmanager.GenerateED25519Key(rand.Reader)
	assert.NoError(t, err)
	err = store.AddKey(key.ID(), "root", key)
	assert.NoError(t, err)

	stores := []trustmanager.KeyStore{store}

	for _, noAnswer := range nos {
		var out bytes.Buffer
		in := bytes.NewBuffer([]byte(noAnswer + "\n"))

		err := removeKeyInteractively(stores, key.ID(), in, &out)
		assert.NoError(t, err)
		text, err := ioutil.ReadAll(&out)
		assert.NoError(t, err)

		output := string(text)
		assert.Contains(t, output, "Are you sure")
		assert.Contains(t, output, "Aborting action")
		assert.Len(t, store.ListKeys(), 1)
	}
}

// If there is one key, asking to remove it will ask for confirmation.  Passing
// 'yes'/'y'/'' response will continue the deletion.
func TestRemoveOneKeyConfirm(t *testing.T) {
	setUp(t)
	yesses := []string{"yes", " Y ", "yE", "   ", ""}

	for _, yesAnswer := range yesses {
		store := trustmanager.NewKeyMemoryStore(ret)

		key, err := trustmanager.GenerateED25519Key(rand.Reader)
		assert.NoError(t, err)
		err = store.AddKey(key.ID(), "root", key)
		assert.NoError(t, err)

		var out bytes.Buffer
		in := bytes.NewBuffer([]byte(yesAnswer + "\n"))

		err = removeKeyInteractively(
			[]trustmanager.KeyStore{store}, key.ID(), in, &out)
		assert.NoError(t, err)
		text, err := ioutil.ReadAll(&out)
		assert.NoError(t, err)

		output := string(text)
		assert.Contains(t, output, "Are you sure")
		assert.Contains(t, output, "Deleted "+key.ID())
		assert.Len(t, store.ListKeys(), 0)
	}
}

// If there is more than one key, removeKeyInteractively will ask which key to
// delete and will do so over and over until the user quits if the answer is
// invalid.
func TestRemoveMultikeysInvalidInput(t *testing.T) {
	setUp(t)
	in := bytes.NewBuffer([]byte("nota number\n9999\n-3\n0"))

	key, err := trustmanager.GenerateED25519Key(rand.Reader)
	assert.NoError(t, err)

	stores := []trustmanager.KeyStore{
		trustmanager.NewKeyMemoryStore(ret),
		trustmanager.NewKeyMemoryStore(ret),
	}

	err = stores[0].AddKey(key.ID(), "root", key)
	assert.NoError(t, err)

	err = stores[1].AddKey("gun/"+key.ID(), "target", key)
	assert.NoError(t, err)

	var out bytes.Buffer

	err = removeKeyInteractively(stores, key.ID(), in, &out)
	assert.Error(t, err)
	text, err := ioutil.ReadAll(&out)
	assert.NoError(t, err)

	assert.Len(t, stores[0].ListKeys(), 1)
	assert.Len(t, stores[1].ListKeys(), 1)

	// It should have listed the keys over and over, asking which key the user
	// wanted to delete
	output := string(text)
	assert.Contains(t, output, "Found the following matching keys")
	var rootCount, targetCount int
	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(line, key.ID()) {
			if strings.Contains(line, "target") {
				targetCount++
			} else {
				rootCount++
			}
		}
	}
	assert.Equal(t, rootCount, targetCount)
	assert.Equal(t, 4, rootCount) // for each of the 4 invalid inputs
}

// If there is more than one key, removeKeyInteractively will ask which key to
// delete.  Then it will confirm whether they want to delete, and the user can
// abort at that confirmation.
func TestRemoveMultikeysAbortChoice(t *testing.T) {
	setUp(t)
	in := bytes.NewBuffer([]byte("1\nn\n"))

	key, err := trustmanager.GenerateED25519Key(rand.Reader)
	assert.NoError(t, err)

	stores := []trustmanager.KeyStore{
		trustmanager.NewKeyMemoryStore(ret),
		trustmanager.NewKeyMemoryStore(ret),
	}

	err = stores[0].AddKey(key.ID(), "root", key)
	assert.NoError(t, err)

	err = stores[1].AddKey("gun/"+key.ID(), "target", key)
	assert.NoError(t, err)

	var out bytes.Buffer

	err = removeKeyInteractively(stores, key.ID(), in, &out)
	assert.NoError(t, err) // no error to abort deleting
	text, err := ioutil.ReadAll(&out)
	assert.NoError(t, err)

	assert.Len(t, stores[0].ListKeys(), 1)
	assert.Len(t, stores[1].ListKeys(), 1)

	// It should have listed the keys, asked whether the user really wanted to
	// delete, and then aborted.
	output := string(text)
	assert.Contains(t, output, "Found the following matching keys")
	assert.Contains(t, output, "Are you sure")
	assert.Contains(t, output, "Aborting action")
}

// If there is more than one key, removeKeyInteractively will ask which key to
// delete.  Then it will confirm whether they want to delete, and if the user
// confirms, will remove it from the correct key store.
func TestRemoveMultikeysRemoveOnlyChosenKey(t *testing.T) {
	setUp(t)
	in := bytes.NewBuffer([]byte("1\ny\n"))

	key, err := trustmanager.GenerateED25519Key(rand.Reader)
	assert.NoError(t, err)

	stores := []trustmanager.KeyStore{
		trustmanager.NewKeyMemoryStore(ret),
		trustmanager.NewKeyMemoryStore(ret),
	}

	err = stores[0].AddKey(key.ID(), "root", key)
	assert.NoError(t, err)

	err = stores[1].AddKey("gun/"+key.ID(), "target", key)
	assert.NoError(t, err)

	var out bytes.Buffer

	err = removeKeyInteractively(stores, key.ID(), in, &out)
	assert.NoError(t, err)
	text, err := ioutil.ReadAll(&out)
	assert.NoError(t, err)

	// It should have listed the keys, asked whether the user really wanted to
	// delete, and then deleted.
	output := string(text)
	assert.Contains(t, output, "Found the following matching keys")
	assert.Contains(t, output, "Are you sure")
	assert.Contains(t, output, "Deleted "+key.ID())

	// figure out which one we picked to delete, and assert it was deleted
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, "\t1.") { // we picked the first item
			if strings.Contains(line, "root") { // first key store
				assert.Len(t, stores[0].ListKeys(), 0)
				assert.Len(t, stores[1].ListKeys(), 1)
			} else {
				assert.Len(t, stores[0].ListKeys(), 1)
				assert.Len(t, stores[1].ListKeys(), 0)
			}
		}
	}
}

// Non-roles, root, and delegation keys can't be rotated with the command line
func TestRotateKeyInvalidRoles(t *testing.T) {
	setUp(t)
	invalids := []string{
		data.CanonicalRootRole,
		"notevenARole",
		"targets/a",
	}
	for _, role := range invalids {
		for _, serverManaged := range []bool{true, false} {
			k := &keyCommander{
				configGetter:           func() (*viper.Viper, error) { return viper.New(), nil },
				getRetriever:           func() passphrase.Retriever { return passphrase.ConstantRetriever("pass") },
				rotateKeyRole:          role,
				rotateKeyServerManaged: serverManaged,
			}
			commands := []string{"gun", role}
			if serverManaged {
				commands = append(commands, "-r")
			}
			err := k.keysRotate(&cobra.Command{}, commands)
			assert.Error(t, err)
			assert.Contains(t, err.Error(),
				fmt.Sprintf("does not currently permit rotating the %s key", role))
		}
	}
}

// Cannot rotate a targets key and require that it is server managed
func TestRotateKeyTargetCannotBeServerManaged(t *testing.T) {
	setUp(t)
	k := &keyCommander{
		configGetter:           func() (*viper.Viper, error) { return viper.New(), nil },
		getRetriever:           func() passphrase.Retriever { return passphrase.ConstantRetriever("pass") },
		rotateKeyRole:          data.CanonicalTargetsRole,
		rotateKeyServerManaged: true,
	}
	err := k.keysRotate(&cobra.Command{}, []string{"gun", data.CanonicalTargetsRole})
	assert.Error(t, err)
	assert.IsType(t, client.ErrInvalidRemoteRole{}, err)
}

// Cannot rotate a timestamp key and require that it is locally managed
func TestRotateKeyTimestampCannotBeLocallyManaged(t *testing.T) {
	setUp(t)
	k := &keyCommander{
		configGetter:           func() (*viper.Viper, error) { return viper.New(), nil },
		getRetriever:           func() passphrase.Retriever { return passphrase.ConstantRetriever("pass") },
		rotateKeyRole:          data.CanonicalTimestampRole,
		rotateKeyServerManaged: false,
	}
	err := k.keysRotate(&cobra.Command{}, []string{"gun", data.CanonicalTimestampRole})
	assert.Error(t, err)
	assert.IsType(t, client.ErrInvalidLocalRole{}, err)
}

// rotate key must be provided with a gun
func TestRotateKeyNoGUN(t *testing.T) {
	setUp(t)
	k := &keyCommander{
		configGetter:  func() (*viper.Viper, error) { return viper.New(), nil },
		getRetriever:  func() passphrase.Retriever { return passphrase.ConstantRetriever("pass") },
		rotateKeyRole: data.CanonicalTargetsRole,
	}
	err := k.keysRotate(&cobra.Command{}, []string{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Must specify a GUN")
}

// initialize a repo with keys, so they can be rotated
func setUpRepo(t *testing.T, tempBaseDir, gun string, ret passphrase.Retriever) (
	*httptest.Server, map[string]string) {

	// Set up server
	ctx := context.WithValue(
		context.Background(), "metaStore", storage.NewMemStorage())

	// Do not pass one of the const KeyAlgorithms here as the value! Passing a
	// string is in itself good test that we are handling it correctly as we
	// will be receiving a string from the configuration.
	ctx = context.WithValue(ctx, "keyAlgorithm", "ecdsa")

	// Eat the logs instead of spewing them out
	l := logrus.New()
	l.Out = bytes.NewBuffer(nil)
	ctx = ctxu.WithLogger(ctx, logrus.NewEntry(l))

	cryptoService := cryptoservice.NewCryptoService(
		"", trustmanager.NewKeyMemoryStore(ret))
	ts := httptest.NewServer(server.RootHandler(nil, ctx, cryptoService, nil, nil))

	repo, err := client.NewNotaryRepository(
		tempBaseDir, gun, ts.URL, http.DefaultTransport, ret)
	assert.NoError(t, err, "error creating repo: %s", err)

	rootPubKey, err := repo.CryptoService.Create("root", data.ECDSAKey)
	assert.NoError(t, err, "error generating root key: %s", err)

	err = repo.Initialize(rootPubKey.ID())
	assert.NoError(t, err)

	return ts, repo.CryptoService.ListAllKeys()
}

// The command line uses NotaryRepository's RotateKey - this is just testing
// that the correct config variables are passed for the client to request a key
// from the remote server.
func TestRotateKeyRemoteServerManagesKey(t *testing.T) {
	for _, role := range []string{data.CanonicalSnapshotRole, data.CanonicalTimestampRole} {
		setUp(t)
		// Temporary directory where test files will be created
		tempBaseDir, err := ioutil.TempDir("/tmp", "notary-test-")
		defer os.RemoveAll(tempBaseDir)
		assert.NoError(t, err, "failed to create a temporary directory: %s", err)
		gun := "docker.com/notary"

		ret := passphrase.ConstantRetriever("pass")

		ts, initialKeys := setUpRepo(t, tempBaseDir, gun, ret)
		defer ts.Close()
		assert.Len(t, initialKeys, 3)

		k := &keyCommander{
			configGetter: func() (*viper.Viper, error) {
				v := viper.New()
				v.SetDefault("trust_dir", tempBaseDir)
				v.SetDefault("remote_server.url", ts.URL)
				return v, nil
			},
			getRetriever:           func() passphrase.Retriever { return ret },
			rotateKeyServerManaged: true,
		}
		assert.NoError(t, k.keysRotate(&cobra.Command{}, []string{gun, role, "-r"}))

		repo, err := client.NewNotaryRepository(tempBaseDir, gun, ts.URL, http.DefaultTransport, ret)
		assert.NoError(t, err, "error creating repo: %s", err)

		cl, err := repo.GetChangelist()
		assert.NoError(t, err, "unable to get changelist: %v", err)
		assert.Len(t, cl.List(), 0, "expected the changes to have been published")

		finalKeys := repo.CryptoService.ListAllKeys()
		// no keys have been created, since a remote key was specified
		if role == data.CanonicalSnapshotRole {
			assert.Len(t, finalKeys, 2)
			for k, r := range initialKeys {
				if r != data.CanonicalSnapshotRole {
					_, ok := finalKeys[k]
					assert.True(t, ok)
				}
			}
		} else {
			assert.Len(t, finalKeys, 3)
			for k := range initialKeys {
				_, ok := finalKeys[k]
				assert.True(t, ok)
			}
		}

	}
}

// The command line uses NotaryRepository's RotateKey - this is just testing
// that multiple keys can be rotated at once locally
func TestRotateKeyBothKeys(t *testing.T) {
	setUp(t)
	// Temporary directory where test files will be created
	tempBaseDir, err := ioutil.TempDir("/tmp", "notary-test-")
	defer os.RemoveAll(tempBaseDir)
	assert.NoError(t, err, "failed to create a temporary directory: %s", err)
	gun := "docker.com/notary"

	ret := passphrase.ConstantRetriever("pass")

	ts, initialKeys := setUpRepo(t, tempBaseDir, gun, ret)
	defer ts.Close()

	k := &keyCommander{
		configGetter: func() (*viper.Viper, error) {
			v := viper.New()
			v.SetDefault("trust_dir", tempBaseDir)
			v.SetDefault("remote_server.url", ts.URL)
			return v, nil
		},
		getRetriever: func() passphrase.Retriever { return ret },
	}
	assert.NoError(t, k.keysRotate(&cobra.Command{}, []string{gun, data.CanonicalTargetsRole}))
	assert.NoError(t, k.keysRotate(&cobra.Command{}, []string{gun, data.CanonicalSnapshotRole}))

	repo, err := client.NewNotaryRepository(tempBaseDir, gun, ts.URL, nil, ret)
	assert.NoError(t, err, "error creating repo: %s", err)

	cl, err := repo.GetChangelist()
	assert.NoError(t, err, "unable to get changelist: %v", err)
	assert.Len(t, cl.List(), 0)

	// two new keys have been created, and the old keys should still be gone
	newKeys := repo.CryptoService.ListAllKeys()
	// there should be 3 keys - snapshot, targets, and root
	assert.Len(t, newKeys, 3)

	// the old snapshot/targets keys should be gone
	for keyID, role := range initialKeys {
		r, ok := newKeys[keyID]
		switch r {
		case data.CanonicalSnapshotRole, data.CanonicalTargetsRole:
			assert.False(t, ok, "original key %s still there", keyID)
		case data.CanonicalRootRole:
			assert.Equal(t, role, r)
			assert.True(t, ok, "old root key has changed")
		}
	}

	found := make(map[string]bool)
	for _, role := range newKeys {
		found[role] = true
	}
	assert.True(t, found[data.CanonicalTargetsRole], "targets key was not created")
	assert.True(t, found[data.CanonicalSnapshotRole], "snapshot key was not created")
	assert.True(t, found[data.CanonicalRootRole], "root key was removed somehow")
}

func TestChangeKeyPassphraseInvalidID(t *testing.T) {
	setUp(t)
	k := &keyCommander{
		configGetter: func() (*viper.Viper, error) { return viper.New(), nil },
		getRetriever: func() passphrase.Retriever { return passphrase.ConstantRetriever("pass") },
	}
	err := k.keyPassphraseChange(&cobra.Command{}, []string{"too_short"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid key ID provided")
}

func TestChangeKeyPassphraseInvalidNumArgs(t *testing.T) {
	setUp(t)
	k := &keyCommander{
		configGetter: func() (*viper.Viper, error) { return viper.New(), nil },
		getRetriever: func() passphrase.Retriever { return passphrase.ConstantRetriever("pass") },
	}
	err := k.keyPassphraseChange(&cobra.Command{}, []string{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "must specify the key ID")
}

func TestChangeKeyPassphraseNonexistentID(t *testing.T) {
	setUp(t)
	k := &keyCommander{
		configGetter: func() (*viper.Viper, error) { return viper.New(), nil },
		getRetriever: func() passphrase.Retriever { return passphrase.ConstantRetriever("pass") },
	}
	// Valid ID size, but does not exist as a key ID
	err := k.keyPassphraseChange(&cobra.Command{}, []string{strings.Repeat("x", notary.Sha256HexSize)})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "could not retrieve local key for key ID provided")
}

func TestKeyImportMismatchingRoles(t *testing.T) {
	setUp(t)
	k := &keyCommander{
		configGetter:   func() (*viper.Viper, error) { return viper.New(), nil },
		getRetriever:   func() passphrase.Retriever { return passphrase.ConstantRetriever("pass") },
		keysImportRole: "targets",
	}
	tempFileName := generateTempTestKeyFile(t, "snapshot")
	defer os.Remove(tempFileName)

	err := k.keysImport(&cobra.Command{}, []string{tempFileName})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "does not match role")
}

func TestKeyImportNoGUNForTargetsPEM(t *testing.T) {
	setUp(t)
	k := &keyCommander{
		configGetter: func() (*viper.Viper, error) { return viper.New(), nil },
		getRetriever: func() passphrase.Retriever { return passphrase.ConstantRetriever("pass") },
	}
	tempFileName := generateTempTestKeyFile(t, "targets")
	defer os.Remove(tempFileName)

	err := k.keysImport(&cobra.Command{}, []string{tempFileName})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Must specify GUN")
}

func TestKeyImportNoGUNForSnapshotPEM(t *testing.T) {
	setUp(t)
	k := &keyCommander{
		configGetter: func() (*viper.Viper, error) { return viper.New(), nil },
		getRetriever: func() passphrase.Retriever { return passphrase.ConstantRetriever("pass") },
	}
	tempFileName := generateTempTestKeyFile(t, "snapshot")
	defer os.Remove(tempFileName)

	err := k.keysImport(&cobra.Command{}, []string{tempFileName})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Must specify GUN")
}

func TestKeyImportNoGUNForTargetsFlag(t *testing.T) {
	setUp(t)
	k := &keyCommander{
		configGetter:   func() (*viper.Viper, error) { return viper.New(), nil },
		getRetriever:   func() passphrase.Retriever { return passphrase.ConstantRetriever("pass") },
		keysImportRole: "targets",
	}
	tempFileName := generateTempTestKeyFile(t, "")
	defer os.Remove(tempFileName)

	err := k.keysImport(&cobra.Command{}, []string{tempFileName})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Must specify GUN")
}

func TestKeyImportNoGUNForSnapshotFlag(t *testing.T) {
	setUp(t)
	k := &keyCommander{
		configGetter:   func() (*viper.Viper, error) { return viper.New(), nil },
		getRetriever:   func() passphrase.Retriever { return passphrase.ConstantRetriever("pass") },
		keysImportRole: "snapshot",
	}
	tempFileName := generateTempTestKeyFile(t, "")
	defer os.Remove(tempFileName)

	err := k.keysImport(&cobra.Command{}, []string{tempFileName})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Must specify GUN")
}

func TestKeyImportNoRole(t *testing.T) {
	setUp(t)
	k := &keyCommander{
		configGetter: func() (*viper.Viper, error) { return viper.New(), nil },
		getRetriever: func() passphrase.Retriever { return passphrase.ConstantRetriever("pass") },
	}
	tempFileName := generateTempTestKeyFile(t, "")
	defer os.Remove(tempFileName)

	err := k.keysImport(&cobra.Command{}, []string{tempFileName})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Could not infer role, and no role was specified for key")
}

func generateTempTestKeyFile(t *testing.T, role string) string {
	setUp(t)
	privKey, err := trustmanager.GenerateECDSAKey(rand.Reader)
	if err != nil {
		return ""
	}
	keyBytes, err := trustmanager.KeyToPEM(privKey, role)
	assert.NoError(t, err)

	tempPrivFile, err := ioutil.TempFile("/tmp", "privfile")
	assert.NoError(t, err)

	// Write the private key to a file so we can import it
	_, err = tempPrivFile.Write(keyBytes)
	assert.NoError(t, err)
	tempPrivFile.Close()
	return tempPrivFile.Name()
}
