package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	_ "github.com/docker/distribution/registry/auth/silly"
	"github.com/docker/notary/server/storage"
	"github.com/docker/notary/tuf/data"
	"github.com/docker/notary/tuf/signed"
	"github.com/docker/notary/tuf/testutils"
	"github.com/docker/notary/utils"
	"github.com/stretchr/testify/assert"
	"golang.org/x/net/context"
)

func TestRunBadAddr(t *testing.T) {
	err := Run(
		context.Background(),
		Config{
			Addr:  "testAddr",
			Trust: signed.NewEd25519(),
		},
	)
	assert.Error(t, err, "Passed bad addr, Run should have failed")
}

func TestRunReservedPort(t *testing.T) {
	ctx, _ := context.WithCancel(context.Background())

	err := Run(
		ctx,
		Config{
			Addr:  "localhost:80",
			Trust: signed.NewEd25519(),
		},
	)

	assert.Error(t, err)
	assert.IsType(t, &net.OpError{}, err)
	assert.True(
		t,
		strings.Contains(err.Error(), "bind: permission denied"),
		"Received unexpected err: %s",
		err.Error(),
	)
}

func TestMetricsEndpoint(t *testing.T) {
	handler := RootHandler(nil, context.Background(), signed.NewEd25519(),
		nil, nil)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	res, err := http.Get(ts.URL + "/metrics")
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, res.StatusCode)
}

// GetKeys supports only the timestamp and snapshot key endpoints
func TestGetKeysEndpoint(t *testing.T) {
	ctx := context.WithValue(
		context.Background(), "metaStore", storage.NewMemStorage())
	ctx = context.WithValue(ctx, "keyAlgorithm", data.ED25519Key)

	handler := RootHandler(nil, ctx, signed.NewEd25519(), nil, nil)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	rolesToStatus := map[string]int{
		data.CanonicalTimestampRole: http.StatusOK,
		data.CanonicalSnapshotRole:  http.StatusOK,
		data.CanonicalTargetsRole:   http.StatusNotFound,
		data.CanonicalRootRole:      http.StatusNotFound,
		"somerandomrole":            http.StatusNotFound,
	}

	for role, expectedStatus := range rolesToStatus {
		res, err := http.Get(
			fmt.Sprintf("%s/v2/gun/_trust/tuf/%s.key", ts.URL, role))
		assert.NoError(t, err)
		assert.Equal(t, expectedStatus, res.StatusCode)
	}
}

// This just checks the URL routing is working correctly and cache headers are set correctly.
// More detailed tests for this path including negative
// tests are located in /server/handlers/
func TestGetRoleByHash(t *testing.T) {
	store := storage.NewMemStorage()

	ts := data.SignedTimestamp{
		Signatures: make([]data.Signature, 0),
		Signed: data.Timestamp{
			Type:    data.TUFTypes[data.CanonicalTimestampRole],
			Version: 1,
			Expires: data.DefaultExpires(data.CanonicalTimestampRole),
		},
	}
	j, err := json.Marshal(&ts)
	assert.NoError(t, err)
	store.UpdateCurrent("gun", storage.MetaUpdate{
		Role:    data.CanonicalTimestampRole,
		Version: 1,
		Data:    j,
	})
	checksumBytes := sha256.Sum256(j)
	checksum := hex.EncodeToString(checksumBytes[:])

	// create and add a newer timestamp. We're going to try and request
	// the older version we created above.
	ts = data.SignedTimestamp{
		Signatures: make([]data.Signature, 0),
		Signed: data.Timestamp{
			Type:    data.TUFTypes[data.CanonicalTimestampRole],
			Version: 2,
			Expires: data.DefaultExpires(data.CanonicalTimestampRole),
		},
	}
	newTS, err := json.Marshal(&ts)
	assert.NoError(t, err)
	store.UpdateCurrent("gun", storage.MetaUpdate{
		Role:    data.CanonicalTimestampRole,
		Version: 1,
		Data:    newTS,
	})

	ctx := context.WithValue(
		context.Background(), "metaStore", store)

	ctx = context.WithValue(ctx, "keyAlgorithm", data.ED25519Key)

	ccc := utils.NewCacheControlConfig(10, false)
	handler := RootHandler(nil, ctx, signed.NewEd25519(), ccc, ccc)
	serv := httptest.NewServer(handler)
	defer serv.Close()

	res, err := http.Get(fmt.Sprintf(
		"%s/v2/gun/_trust/tuf/%s.%s.json",
		serv.URL,
		data.CanonicalTimestampRole,
		checksum,
	))
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, res.StatusCode)
	// if content is equal, checksums are guaranteed to be equal
	verifyGetResponse(t, res, j)
}

// This just checks the URL routing is working correctly and cache headers are set correctly.
// More detailed tests for this path including negative
// tests are located in /server/handlers/
func TestGetCurrentRole(t *testing.T) {
	store := storage.NewMemStorage()
	metadata, _, err := testutils.NewRepoMetadata("gun")
	assert.NoError(t, err)

	// need both the snapshot and the timestamp, because when getting the current
	// timestamp the server checks to see if it's out of date (there's a new snapshot)
	// and if so, generates a new one
	store.UpdateCurrent("gun", storage.MetaUpdate{
		Role:    data.CanonicalSnapshotRole,
		Version: 1,
		Data:    metadata[data.CanonicalSnapshotRole],
	})
	store.UpdateCurrent("gun", storage.MetaUpdate{
		Role:    data.CanonicalTimestampRole,
		Version: 1,
		Data:    metadata[data.CanonicalTimestampRole],
	})

	ctx := context.WithValue(
		context.Background(), "metaStore", store)

	ctx = context.WithValue(ctx, "keyAlgorithm", data.ED25519Key)

	ccc := utils.NewCacheControlConfig(10, false)
	handler := RootHandler(nil, ctx, signed.NewEd25519(), ccc, ccc)
	serv := httptest.NewServer(handler)
	defer serv.Close()

	res, err := http.Get(fmt.Sprintf(
		"%s/v2/gun/_trust/tuf/%s.json",
		serv.URL,
		data.CanonicalTimestampRole,
	))
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, res.StatusCode)
	verifyGetResponse(t, res, metadata[data.CanonicalTimestampRole])
}

// Verifies that the body is as expected  and that there are cache control headers
func verifyGetResponse(t *testing.T, r *http.Response, expectedBytes []byte) {
	body, err := ioutil.ReadAll(r.Body)
	assert.NoError(t, err)
	assert.True(t, bytes.Equal(expectedBytes, body))

	assert.NotEqual(t, "", r.Header.Get("Cache-Control"))
	assert.NotEqual(t, "", r.Header.Get("Last-Modified"))
	assert.Equal(t, "", r.Header.Get("Pragma"))
}
