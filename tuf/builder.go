package tuf

import (
	"encoding/json"
	"fmt"

	"github.com/Sirupsen/logrus"
	"github.com/docker/notary/certs"
	"github.com/docker/notary/trustmanager"
	"github.com/docker/notary/tuf/data"
	"github.com/docker/notary/tuf/signed"
)

// ErrBuildDone is returned when any functions are called on RepoBuilder, and it
// is already finished building
type ErrBuildDone struct{}

func (e ErrBuildDone) Error() string {
	return "the builder is done building and cannot accept any more input or produce any more output"
}

// ErrBuildFailed is returned when any functions are called on RepoBuilder, and it
// is already failed building and will not accept any other data
type ErrBuildFailed struct{}

func (e ErrBuildFailed) Error() string {
	return "the builder has failed building and cannot accept any more input or produce any more output"
}

// ErrInvalidBuilderInput is returned when RepoBuilder.Load is called
// with the wrong type of metadata for thes tate that it's in
type ErrInvalidBuilderInput struct{ msg string }

func (e ErrInvalidBuilderInput) Error() string {
	return e.msg
}

// RepoBuilder is an interface for an object which builds a tuf.Repo
type RepoBuilder interface {
	Load(roleName string, content []byte, minVersion int) error
	LoadRoot(content []byte, minVersion int) error
	LoadSnapshot(content []byte, minVersion int) error
	LoadTimestamp(content []byte, minVersion int) error
	LoadTargets(content []byte, minVersion int) error
	LoadDelegation(role string, content []byte, minVersion int) error
	Finish() (*Repo, error)
	BootstrapNewBuilder() RepoBuilder
	GetRepo() *Repo
}

// NewRepoBuilder is the only way to get a pre-built RepoBuilder
func NewRepoBuilder(certStore trustmanager.X509Store, gun string, cs signed.CryptoService,
	rootRole *data.BaseRole, rootChecksummer data.ChecksumValidator) RepoBuilder {

	return &repoBuilder{
		repo:                 NewRepo(cs),
		rootRole:             rootRole,
		rootChecksummer:      rootChecksummer,
		gun:                  gun,
		certStore:            certStore,
		cs:                   cs,
		loadedNotChecksummed: make(map[string][]byte),
	}
}

type repoBuilder struct {
	finished bool
	failed   bool
	repo     *Repo

	// needed for root trust pininng verification
	gun       string
	certStore trustmanager.X509Store

	// in case we load root and/or targets before snapshot and timestamp (
	// or snapshot and not timestamp), so we know what to verify when the
	// data with checksums come in
	loadedNotChecksummed map[string][]byte

	// needed for bootstrapping a builder to validate a new root
	rootRole        *data.BaseRole
	rootChecksummer data.ChecksumValidator

	// needed for TUF completeness
	cs signed.CryptoService
}

func (rb *repoBuilder) GetRepo() *Repo {
	return rb.repo
}

func (rb *repoBuilder) Finish() (*Repo, error) {
	if rb.finished {
		return nil, ErrBuildDone{}
	}

	rb.finished = true
	return rb.repo, nil
}

func (rb *repoBuilder) BootstrapNewBuilder() RepoBuilder {
	rootRole := rb.rootRole
	rootChecksummer := rb.rootChecksummer

	if rb.repo.Root != nil {
		roleObj, err := rb.repo.Root.BuildBaseRole(data.CanonicalRootRole)
		if err == nil { // this should always be true, since it was already validated
			rootRole = &roleObj
		}
	}
	if rb.repo.Snapshot != nil {
		rootChecksummer = rb.repo.Snapshot.Signed.Meta[data.CanonicalRootRole]
	}

	return NewRepoBuilder(rb.certStore, rb.gun, rb.cs, rootRole, rootChecksummer)
}

func (rb *repoBuilder) Load(roleName string, content []byte, minVersion int) error {
	switch roleName {
	case data.CanonicalRootRole:
		return rb.LoadRoot(content, minVersion)
	case data.CanonicalSnapshotRole:
		return rb.LoadSnapshot(content, minVersion)
	case data.CanonicalTimestampRole:
		return rb.LoadTimestamp(content, minVersion)
	case data.CanonicalTargetsRole:
		return rb.LoadTargets(content, minVersion)
	default:
		return rb.LoadDelegation(roleName, content, minVersion)
	}
}

// LoadRoot loads a root if one has not been loaded
func (rb *repoBuilder) LoadRoot(content []byte, minVersion int) error {
	roleName := data.CanonicalRootRole
	switch {
	case rb.repo.Root != nil:
		return ErrInvalidBuilderInput{"msg: root has already been loaded"}
	case rb.failed:
		return ErrBuildFailed{}
	case rb.finished:
		return ErrBuildDone{}
	}

	signedObj, err := rb.bytesToSigned(roleName, content, rb.rootChecksummer)
	if err != nil {
		return err
	}

	if err := rb.verifyPinnedTrust(signedObj); err != nil {
		return err
	}

	// verify that the metadata structure is correct - we need this in order to get
	// the root role to verify that signatures are self-consistent
	signedRoot, err := data.RootFromSigned(signedObj)
	if err != nil {
		return err
	}

	rootRole, err := signedRoot.BuildBaseRole(roleName)
	if err != nil { // this should never happen, since it's already been validated
		return err
	}
	// validate that the signatures for the root are consistent with its own definitions
	if err := signed.Verify(signedObj, rootRole, minVersion); err != nil {
		return err
	}

	rb.repo.SetRoot(signedRoot)
	return nil
}

// validate against old keys or pinned trust certs
func (rb *repoBuilder) verifyPinnedTrust(signedObj *data.Signed) error {
	if rb.rootRole == nil {
		// TODO: certs.ValidateRoot should only check the trust pinning - we will
		// validate that the root is self-consistent with itself later
		// it also calls RootToSigned, so there are some inefficiencies here
		if err := certs.ValidateRoot(rb.certStore, signedObj, rb.gun); err != nil {
			logrus.Debug("TUF repo builder: root failed validation against trust certificates")
			return err
		}
	} else {
		// verify with existing keys rather than trust pinning
		if err := signed.VerifySignatures(signedObj, *rb.rootRole); err != nil {
			logrus.Debug("TUF repo builder: root failed validation against previous root keys")
			return err
		}
	}
	return nil
}

func (rb *repoBuilder) LoadTimestamp(content []byte, minVersion int) error {
	roleName := data.CanonicalTimestampRole
	switch {
	case rb.repo.Timestamp != nil:
		return ErrInvalidBuilderInput{msg: "timestamp has already been loaded"}
	case rb.repo.Root == nil:
		return ErrInvalidBuilderInput{msg: "root must be loaded first"}
	case rb.failed:
		return ErrBuildFailed{}
	case rb.finished:
		return ErrBuildDone{}
	}
	timestampRole, err := rb.repo.Root.BuildBaseRole(roleName)
	if err != nil { // this should never happen, since it's already been validated
		return err
	}

	signedObj, err := rb.bytesToSignedAndValidateSigs(timestampRole, content, minVersion)
	if err != nil {
		return err
	}

	signedTimestamp, err := data.TimestampFromSigned(signedObj)
	if err != nil {
		return err
	}

	rb.repo.SetTimestamp(signedTimestamp)
	return rb.validateChecksums(roleName, signedTimestamp.Signed.Meta)
}

func (rb *repoBuilder) LoadSnapshot(content []byte, minVersion int) error {
	roleName := data.CanonicalSnapshotRole
	switch {
	case rb.repo.Snapshot != nil:
		return ErrInvalidBuilderInput{msg: "snapshot has already been loaded"}
	case rb.repo.Root == nil:
		return ErrInvalidBuilderInput{msg: "root must be loaded first"}
	case rb.failed:
		return ErrBuildFailed{}
	case rb.finished:
		return ErrBuildDone{}
	}
	snapshotRole, err := rb.repo.Root.BuildBaseRole(roleName)
	if err != nil { // this should never happen, since it's already been validated
		return err
	}

	signedObj, err := rb.bytesToSignedAndValidateSigs(snapshotRole, content, minVersion)
	if err != nil {
		return err
	}

	signedSnapshot, err := data.SnapshotFromSigned(signedObj)
	if err != nil {
		return err
	}

	rb.repo.SetSnapshot(signedSnapshot)
	return rb.validateChecksums(roleName, signedSnapshot.Signed.Meta)
}

func (rb *repoBuilder) LoadTargets(content []byte, minVersion int) error {
	roleName := data.CanonicalTargetsRole
	switch {
	case rb.repo.Targets[roleName] != nil:
		return ErrInvalidBuilderInput{msg: "targets has already been loaded"}
	case rb.repo.Root == nil:
		return ErrInvalidBuilderInput{msg: "root must be loaded first"}
	case rb.failed:
		return ErrBuildFailed{}
	case rb.finished:
		return ErrBuildDone{}
	}
	targetsRole, err := rb.repo.Root.BuildBaseRole(roleName)
	if err != nil { // this should never happen, since it's already been validated
		return err
	}

	signedObj, err := rb.bytesToSignedAndValidateSigs(targetsRole, content, minVersion)
	if err != nil {
		return err
	}

	signedTargets, err := data.TargetsFromSigned(signedObj, roleName)
	if err != nil {
		return err
	}

	rb.repo.SetTargets(roleName, signedTargets)
	return nil
}

func (rb *repoBuilder) LoadDelegation(roleName string, content []byte, minVersion int) error {

	switch {
	case !data.IsDelegation(roleName):
		return ErrInvalidBuilderInput{msg: fmt.Sprintf("%s is not a delegation")}
	case rb.repo.Targets[roleName] != nil:
		return ErrInvalidBuilderInput{msg: fmt.Sprintf("%s has already been loaded")}
	case rb.repo.Targets[data.CanonicalTargetsRole] == nil:
		return ErrInvalidBuilderInput{msg: "targets must be loaded first"}
	case rb.failed:
		return ErrBuildFailed{}
	case rb.finished:
		return ErrBuildDone{}
	}
	delegationRole, err := rb.repo.GetDelegationRole(roleName)
	if err != nil {
		return err
	}

	signedObj, err := rb.bytesToSignedAndValidateSigs(delegationRole.BaseRole, content, minVersion)
	if err != nil {
		return err
	}

	signedTargets, err := data.TargetsFromSigned(signedObj, roleName)
	if err != nil {
		return err
	}

	rb.repo.SetTargets(roleName, signedTargets)
	return nil
}

func (rb *repoBuilder) validateChecksums(roleContainingMeta string, f data.ChecksumValidator) error {
	switch roleContainingMeta {
	case data.CanonicalTimestampRole:
		sn, ok := rb.loadedNotChecksummed[data.CanonicalSnapshotRole]
		if ok {
			delete(rb.loadedNotChecksummed, data.CanonicalSnapshotRole)
			err := f.ValidateChecksum(sn, data.CanonicalSnapshotRole)
			if err != nil {
				rb.failed = true
			}
			return err
		}

	default: // snapshot
		for roleName, loadedBytes := range rb.loadedNotChecksummed {
			if roleName != data.CanonicalSnapshotRole {
				delete(rb.loadedNotChecksummed, roleName)
				if err := f.ValidateChecksum(loadedBytes, roleName); err != nil {
					rb.failed = true
					return err
				}
			}
		}
	}
	return nil
}

// Checksums the given bytes, and if they validate, convert to a data.Signed object.
// If a checksummer is not provided, adds the bytes to the list of roles that haven't
// been checksummed.
func (rb *repoBuilder) bytesToSigned(role string, content []byte, checksummer data.ChecksumValidator) (
	*data.Signed, error) {

	if checksummer != nil {
		if err := checksummer.ValidateChecksum(content, role); err != nil {
			return nil, err
		}
	} else if role != data.CanonicalTimestampRole {
		// timestamp is the only role which does not need to be checksummed
		rb.loadedNotChecksummed[role] = content
	}

	// unmarshal to signed
	signedObj := &data.Signed{}
	if err := json.Unmarshal(content, signedObj); err != nil {
		return nil, err
	}

	return signedObj, nil
}

func (rb *repoBuilder) bytesToSignedAndValidateSigs(role data.BaseRole, content []byte, minVersion int) (
	*data.Signed, error) {

	signedObj, err := rb.bytesToSigned(role.Name, content, rb.getChecksummerFor(role.Name))
	if err != nil {
		return nil, err
	}

	// verify signature, version, and expiry
	if err := signed.Verify(signedObj, role, minVersion); err != nil {
		return nil, err
	}

	return signedObj, nil
}

func (rb *repoBuilder) getChecksummerFor(role string) data.ChecksumValidator {
	switch role {
	case data.CanonicalTimestampRole:
		return nil
	case data.CanonicalSnapshotRole:
		if rb.repo.Timestamp == nil {
			return nil
		}
		return &(rb.repo.Timestamp.Signed.Meta)
	default:
		if rb.repo.Snapshot == nil {
			return nil
		}
		return &(rb.repo.Snapshot.Signed.Meta)
	}
}
