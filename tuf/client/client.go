package client

import (
	"encoding/json"

	"github.com/Sirupsen/logrus"
	"github.com/docker/notary"
	tuf "github.com/docker/notary/tuf"
	"github.com/docker/notary/tuf/data"
	"github.com/docker/notary/tuf/store"
	"github.com/docker/notary/tuf/utils"
)

// Client is a usability wrapper around a raw TUF repo
type Client struct {
	remote  store.RemoteStore
	cache   store.MetadataStore
	builder tuf.RepoBuilder
}

// NewClient initialized a Client with the given repo, remote source of content, and cache
func NewClient(builder tuf.RepoBuilder, remote store.RemoteStore, cache store.MetadataStore) *Client {
	return &Client{
		builder: builder,
		remote:  remote,
		cache:   cache,
	}
}

// Update performs an update to the TUF repo as defined by the TUF spec
func (c *Client) Update() error {
	// 1. Get timestamp
	//   a. If timestamp error (verification, expired, etc...) download new root and return to 1.
	// 2. Check if local snapshot is up to date
	//   a. If out of date, get updated snapshot
	//     i. If snapshot error, download new root and return to 1.
	// 3. Check if root correct against snapshot
	//   a. If incorrect, download new root and return to 1.
	// 4. Iteratively download and search targets and delegations to find target meta
	logrus.Debug("updating TUF client")
	snapshot, err := c.update()
	if err != nil {
		logrus.Debug("Error occurred. Root will be downloaded and another update attempted")
		c.builder = c.builder.Retry()
		if err := c.downloadRoot(snapshot); err != nil {
			logrus.Debug("Client Update (Root):", err)
			return err
		}
		// If we error again, we now have the latest root and just want to fail
		// out as there's no expectation the problem can be resolved automatically
		logrus.Debug("retrying TUF client update")
		_, err := c.update()
		return err
	}
	return nil
}

func (c *Client) update() (*data.SignedSnapshot, error) {
	timestamp, err := c.downloadTimestamp()
	if err != nil {
		logrus.Debugf("Client Update (Timestamp): %s", err.Error())
		return nil, err
	}
	snapshot, err := c.downloadSnapshot(*timestamp)
	if err != nil {
		logrus.Debugf("Client Update (Snapshot): %s", err.Error())
		return snapshot, err
	}
	// will always need top level targets at a minimum
	err = c.downloadTargets(*snapshot)
	if err != nil {
		logrus.Debugf("Client Update (Targets): %s", err.Error())
		return snapshot, err
	}
	return snapshot, nil
}

// downloadRoot is responsible for downloading the root.json
func (c *Client) downloadRoot(snapshot *data.SignedSnapshot) error {
	logrus.Debug("Downloading Root...")
	role := data.CanonicalRootRole
	// We can't read an exact size for the root metadata without risking getting stuck in the TUF update cycle
	// since it's possible that downloading timestamp/snapshot metadata may fail due to a signature mismatch
	var size int64 = -1
	var expectedSha256 []byte
	if snapshot != nil {
		size = snapshot.Signed.Meta[role].Length
		expectedSha256 = snapshot.Signed.Meta[role].Hashes["sha256"]
	}

	// if we're bootstrapping we may not have a cached root, an
	// error will result in the "previous root version" being
	// interpreted as 0.
	var err error
	var cachedRoot []byte
	version := 0

	if expectedSha256 != nil {
		// can only trust cache if we have an expected sha256 to trust
		cachedRoot, err = c.cache.GetMeta(role, size)
	}

	if cachedRoot == nil || err != nil {
		logrus.Debug("didn't find a cached root, must download")
	} else {
		err := c.builder.Load(data.CanonicalRootRole, cachedRoot, version)
		if err == nil {
			logrus.Debug("successfully verified cached root")
			return nil
		}
		signedMeta := &data.SignedMeta{}
		if err := json.Unmarshal(cachedRoot, signedMeta); err == nil {
			version = signedMeta.Signed.Version
		}
	}

	raw, err := c.downloadSigned(role, size, expectedSha256)
	if err != nil {
		return err
	}
	err = c.builder.Load(data.CanonicalRootRole, raw, version)
	if err == nil {
		logrus.Debug("successfully verified downloaded root")
		c.cache.SetMeta(data.CanonicalRootRole, raw)
	}
	return err
}

// downloadTimestamp is responsible for downloading the timestamp.json
// Timestamps are special in that we ALWAYS attempt to download and only
// use cache if the download fails (and the cache is still valid).
func (c *Client) downloadTimestamp() (*data.SignedTimestamp, error) {
	logrus.Debug("Downloading Timestamp...")
	role := data.CanonicalTimestampRole

	// We may not have a cached timestamp if this is the first time
	// we're interacting with the repo. This will result in the
	// version being 0
	var (
		old     []byte
		ts      = &data.SignedTimestamp{}
		version = 0
	)
	cachedTS, err := c.cache.GetMeta(role, notary.MaxTimestampSize)
	if err == nil {
		cached := &data.SignedMeta{}
		err := json.Unmarshal(cachedTS, cached)
		if err == nil {
			version = cached.Signed.Version
			old = cachedTS
		}
	}
	// unlike root, targets and snapshot, always try and download timestamps
	// from remote, only using the cache one if we couldn't reach remote.
	raw, err := c.downloadSigned(role, notary.MaxTimestampSize, nil)
	if err == nil {
		err = c.builder.Load(role, raw, version)
		if err == nil {
			logrus.Debug("successfully verified downloaded timestamp")
			c.cache.SetMeta(role, raw)
			json.Unmarshal(raw, ts) // we know it won't error since we vetted it already
			return ts, nil
		}
	}
	if old == nil {
		// couldn't retrieve valid data from server and don't have unmarshallable data in cache.
		logrus.Debug("no cached timestamp available")
		return nil, err
	}
	logrus.Debug(err.Error())
	logrus.Warn("Error while downloading remote metadata, using cached timestamp - this might not be the latest version available remotely")

	err = c.builder.Load(role, old, version)
	if err == nil {
		logrus.Debug("successfully verified cached timestamp")
		json.Unmarshal(old, ts) // we know it won't error since we vetted it already
		return ts, nil
	}
	return nil, err
}

// downloadSnapshot is responsible for downloading the snapshot.json
func (c *Client) downloadSnapshot(ts data.SignedTimestamp) (*data.SignedSnapshot, error) {
	logrus.Debug("Downloading Snapshot...")
	role := data.CanonicalSnapshotRole
	// we're expecting it's previously been vetted
	size := ts.Signed.Meta[role].Length
	expectedSha256 := ts.Signed.Meta[role].Hashes["sha256"]

	sn := &data.SignedSnapshot{}
	version := 0

	raw, err := c.cache.GetMeta(role, size)
	if raw == nil || err != nil {
		logrus.Debug("no snapshot in cache, must download")
	} else {
		err = c.builder.Load(data.CanonicalSnapshotRole, raw, version)
		if err == nil {
			logrus.Debug("using cached snapshot")
			json.Unmarshal(raw, sn) // we know it won't error since we vetted it already
			return sn, nil
		}
		cached := &data.SignedMeta{}
		if err := json.Unmarshal(raw, cached); err == nil {
			version = cached.Signed.Version
		}
	}

	logrus.Debug("cached snapshot invalid, must download: ", err)

	raw, err = c.downloadSigned(role, size, expectedSha256)
	if err != nil {
		return nil, err
	}
	err = c.builder.Load(data.CanonicalSnapshotRole, raw, version)
	if err == nil {
		logrus.Debug("successfully verified downloaded snapshot")
		c.cache.SetMeta(data.CanonicalSnapshotRole, raw)
		json.Unmarshal(raw, sn) // we know it won't error since we vetted it already
		return sn, nil
	}
	return nil, err
}

// downloadTargets downloads all targets and delegated targets for the repository.
// It uses a pre-order tree traversal as it's necessary to download parents first
// to obtain the keys to validate children.
func (c *Client) downloadTargets(snap data.SignedSnapshot) error {
	logrus.Debug("Downloading Targets...")
	toDownload := []data.DelegationRole{{
		BaseRole: data.BaseRole{Name: data.CanonicalTargetsRole},
		Paths:    []string{""},
	}}
	for len(toDownload) > 0 {
		role := toDownload[0]
		toDownload = toDownload[1:]

		children, err := c.getTargetsFile(role.Name, snap)
		if err != nil {
			if _, ok := err.(data.ErrMissingMeta); ok && role.Name != data.CanonicalTargetsRole {
				// if the role meta hasn't been published,
				// that's ok, continue
				continue
			}
			logrus.Error("Error getting targets file: ", role.Name, ": ", err)
			return err
		}
		toDownload = append(children, toDownload...)
	}
	return nil
}

func (c *Client) downloadSigned(role string, size int64, expectedSha256 []byte) ([]byte, error) {
	rolePath := utils.ConsistentName(role, expectedSha256)
	return c.remote.GetMeta(rolePath, size)
}

func (c Client) getTargetsFile(role string, snapshot data.SignedSnapshot) ([]data.DelegationRole, error) {
	roleMeta, err := snapshot.GetMeta(role)
	if err != nil {
		return nil, err
	}
	expectedSha256 := roleMeta.Hashes["sha256"]

	tgs := &data.SignedTargets{}
	version := 0
	raw, err := c.cache.GetMeta(role, roleMeta.Length)
	if err != nil || raw == nil {
		logrus.Debugf("Couldn't not find cached %s, must download", role)
	} else {
		err = c.builder.Load(role, raw, version)
		if err == nil {
			logrus.Debugf("using cached %s", role)
			json.Unmarshal(raw, tgs) // we know it won't error since we vetted it already
			return tgs.GetDelegations(""), nil
		}
	}

	logrus.Debugf("cached %s invalid: %s", role, err)

	raw, err = c.downloadSigned(role, roleMeta.Length, expectedSha256)
	if err != nil {
		return nil, err
	}

	err = c.builder.Load(role, raw, version)
	if err == nil {
		logrus.Debugf("successfully verified downloaded %s", role)
		c.cache.SetMeta(role, raw)
		json.Unmarshal(raw, tgs) // we know it won't error since we vetted it already
		return tgs.GetValidDelegations(""), nil
	}

	return nil, err
}
