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
		logrus.Debug("Resetting the TUF builder...")
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
	logrus.Debug("Loading root...")
	role := data.CanonicalRootRole

	// We can't read an exact size for the root metadata without risking getting stuck in the TUF update cycle
	// since it's possible that downloading timestamp/snapshot metadata may fail due to a signature mismatch
	var size int64 = -1
	var expectedSha256 []byte
	if snapshot != nil {
		size = snapshot.Signed.Meta[role].Length
		expectedSha256 = snapshot.Signed.Meta[role].Hashes["sha256"]
	}

	_, err := c.tryLoadCacheThenRemote(role, size, expectedSha256)
	return err
}

// downloadTimestamp is responsible for downloading the timestamp.json
// Timestamps are special in that we ALWAYS attempt to download and only
// use cache if the download fails (and the cache is still valid).
func (c *Client) downloadTimestamp() (*data.SignedTimestamp, error) {
	logrus.Debug("Loading timestamp...")
	role := data.CanonicalTimestampRole
	ts := &data.SignedTimestamp{}

	// get the cached timestamp, if it exists
	cachedTS, cachedErr := c.cache.GetMeta(role, notary.MaxTimestampSize)
	// always get the remote timestamp, since it supercedes the local one
	remoteTS, remoteErr := c.tryLoadRemote(role, notary.MaxTimestampSize, nil, cachedTS)

	switch {
	case remoteErr == nil:
		json.Unmarshal(remoteTS, ts)
	case cachedErr == nil:
		logrus.Debug(remoteErr.Error())
		logrus.Warn("Error while downloading remote metadata, using cached timestamp - this might not be the latest version available remotely")

		if err := c.builder.Load(role, cachedTS, 0); err != nil {
			return nil, err
		}

		logrus.Debug("successfully verified cached timestamp")
		json.Unmarshal(cachedTS, ts)
	default:
		logrus.Debug("no cached or remote timestamp available")
		return nil, remoteErr
	}

	return ts, nil
}

// downloadSnapshot is responsible for downloading the snapshot.json
func (c *Client) downloadSnapshot(ts data.SignedTimestamp) (*data.SignedSnapshot, error) {
	logrus.Debug("Loading snapshot...")
	role := data.CanonicalSnapshotRole
	sn := &data.SignedSnapshot{}

	// we're expecting it's previously been vetted
	size := ts.Signed.Meta[role].Length
	expectedSha256 := ts.Signed.Meta[role].Hashes["sha256"]

	raw, err := c.tryLoadCacheThenRemote(role, size, expectedSha256)
	if raw != nil {
		if e := json.Unmarshal(raw, sn); e == nil {
			return sn, err
		}
	}
	return nil, err
}

// downloadTargets downloads all targets and delegated targets for the repository.
// It uses a pre-order tree traversal as it's necessary to download parents first
// to obtain the keys to validate children.
func (c *Client) downloadTargets(snap data.SignedSnapshot) error {
	toDownload := []data.DelegationRole{{
		BaseRole: data.BaseRole{Name: data.CanonicalTargetsRole},
		Paths:    []string{""},
	}}
	for len(toDownload) > 0 {
		role := toDownload[0]
		toDownload = toDownload[1:]

		children, err := c.getTargetsFile(role, snap)
		if err != nil {
			if _, ok := err.(data.ErrMissingMeta); ok && role.Name != data.CanonicalTargetsRole {
				// if the role meta hasn't been published,
				// that's ok, continue
				continue
			}
			logrus.Debugf("Error getting %s: %s", role.Name, err)
			return err
		}
		toDownload = append(children, toDownload...)
	}
	return nil
}

func (c Client) getTargetsFile(role data.DelegationRole, snapshot data.SignedSnapshot) ([]data.DelegationRole, error) {
	logrus.Debugf("Loading %s...", role.Name)
	tgs := &data.SignedTargets{}

	// we're expecting it's previously been vetted
	roleMeta, err := snapshot.GetMeta(role.Name)
	if err != nil {
		return nil, err
	}
	expectedSha256 := roleMeta.Hashes["sha256"]
	size := roleMeta.Length

	raw, err := c.tryLoadCacheThenRemote(role.Name, size, expectedSha256)
	if err != nil {
		return nil, err
	}

	json.Unmarshal(raw, tgs)
	return tgs.GetValidDelegations(role), nil
}

func (c *Client) tryLoadCacheThenRemote(role string, size int64, expectedSha256 []byte) ([]byte, error) {
	cachedTS, err := c.cache.GetMeta(role, size)
	if err != nil {
		logrus.Debugf("no %s in cache, must download", role)
		return c.tryLoadRemote(role, size, expectedSha256, nil)
	}

	if err = c.builder.Load(role, cachedTS, 0); err == nil {
		logrus.Debugf("successfully verified cached %s", role)
		return cachedTS, nil
	}

	logrus.Debugf("cached %s is invalid (must download): %s", role, err)
	return c.tryLoadRemote(role, size, expectedSha256, cachedTS)
}

func (c *Client) tryLoadRemote(role string, size int64, expectedSha256, old []byte) ([]byte, error) {
	rolePath := utils.ConsistentName(role, expectedSha256)
	raw, err := c.remote.GetMeta(rolePath, size)
	if err != nil {
		logrus.Debugf("error downloading %s: %s", role, err)
		return old, err
	}
	minVersion := 0
	if old != nil && len(old) > 0 {
		oldSignedMeta := &data.SignedMeta{}
		if readOldErr := json.Unmarshal(old, oldSignedMeta); readOldErr == nil {
			minVersion = oldSignedMeta.Signed.Version
		}
	}
	if err := c.builder.Load(role, raw, minVersion); err != nil {
		logrus.Debugf("downloaded %s is invalid: %s", role, err)
		return raw, err
	}
	logrus.Debugf("successfully verified downloaded %s", role)
	if err := c.cache.SetMeta(role, raw); err != nil {
		logrus.Debugf("Unable to write %s to cache: %s", role, err)
	}
	return raw, nil
}
