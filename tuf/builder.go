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

type ErrBuildDone struct{}

func (e ErrBuildDone) Error() string {
	return "the builder is done building and cannot accept any more input or produce any more output"
}

type ErrInvalidState struct{}

func (e ErrInvalidState) Error() string {
	return "the builder is in an invalid state and cannot recover"
}

type ErrInvalidInputForBuilderState struct{ expectedRoleType string }

func (e ErrInvalidInputForBuilderState) Error() string {
	return fmt.Sprintf(
		"the builder is in a state where it is only accepting %s metadata", e.expectedRoleType)
}

type RepoBuilder interface {
	Load(roleName string, content []byte, minVersion int) error
	Finish() (*Repo, error)
	Retry() RepoBuilder
}

func NewRepoBuilder(certStore trustmanager.X509Store, gun string,
	rootRole *data.BaseRole, checksum data.ChecksumValidator) RepoBuilder {

	return &repoBuilder{
		repo: NewRepo(nil),
		currentState: loadRootState{
			rootRole:    rootRole,
			checksummer: checksum,
			gun:         gun,
			certStore:   certStore,
		},
		gun:       gun,
		certStore: certStore,
	}
}

// builderState is an interface for one state of the builder
type builderState interface {
	// Input validates the content, and if valid, sets it on the repo
	load(repo *Repo, roleName string, content []byte, minVersion int) error
}

type repoBuilder struct {
	repo         *Repo
	currentState builderState
	loadedRoot   []byte
	gun          string
	certStore    trustmanager.X509Store
}

func (rb *repoBuilder) Retry() RepoBuilder {
	var rootRole *data.BaseRole
	var checksum data.ChecksumValidator

	switch rb.currentState.(type) {

	case loadTargetsState, loadDelegationState:
		checksum = rb.repo.Snapshot.Signed.Meta[data.CanonicalRootRole]
		r := rb.repo.Root.GetRole(data.CanonicalRootRole)
		rootRole = &r
	case loadTimestampState, loadSnapshotState:
		r := rb.repo.Root.GetRole(data.CanonicalRootRole)
		rootRole = &r
	}

	return NewRepoBuilder(rb.certStore, rb.gun, rootRole, checksum)
}

func (rb *repoBuilder) Finish() (*Repo, error) {
	switch rb.currentState.(type) {

	case loadRootState, loadTimestampState, loadSnapshotState, loadTargetsState, loadDelegationState:
		rb.currentState = buildingDoneState{}
		return rb.repo, nil

	case buildingDoneState:
		return nil, ErrBuildDone{}
	default: // we should never get here, since repoBuilder is unexported
		return nil, ErrInvalidState{}
	}
}

func (rb *repoBuilder) Load(roleName string, content []byte, minVersion int) error {
	// decide whether or not to load the input at all, given the current state
	switch rb.currentState.(type) {
	case loadRootState, loadTimestampState, loadSnapshotState, loadTargetsState, loadDelegationState:
		if err := rb.currentState.load(rb.repo, roleName, content, minVersion); err != nil {
			return err
		}
	case buildingDoneState:
		return ErrBuildDone{}
	default: // we should never get here, since repoBuilder is unexported
		return ErrInvalidState{}
	}

	// We were in a valid state, we loaded in some input, and it succeeded.  Now handle the state
	// transitions
	switch rb.currentState.(type) {
	case loadRootState:
		rb.loadedRoot = content
		rb.currentState = loadTimestampState{
			role: rb.repo.Root.GetRole(data.CanonicalTimestampRole)}

	case loadTimestampState:
		rb.currentState = loadSnapshotState{
			role:        rb.repo.Root.GetRole(data.CanonicalSnapshotRole),
			checksummer: rb.repo.Timestamp.Signed.Meta,
			loadedRoot:  rb.loadedRoot,
		}

	case loadSnapshotState:
		rb.currentState = loadTargetsState{
			role:        rb.repo.Root.GetRole(data.CanonicalTargetsRole),
			checksummer: rb.repo.Snapshot.Signed.Meta,
		}

	case loadTargetsState, loadDelegationState:
		rb.currentState = loadDelegationState{
			targetsTree: rb.repo.Targets[data.CanonicalTargetsRole],
			checksummer: rb.repo.Snapshot.Signed.Meta,
		}

	default:
		// do not transition in any way
	}
	return nil
}

func bytesToSigned(content []byte, name string, checksummer data.ChecksumValidator) (*data.Signed, error) {
	// Validate checksum first
	if checksummer != nil {
		if err := checksummer.ValidateChecksum(content, name); err != nil {
			return nil, err
		}
	}

	// unmarshal to signed
	signedObj := &data.Signed{}
	if err := json.Unmarshal(content, signedObj); err != nil {
		return nil, err
	}

	return signedObj, nil
}

// ---- load root state ----

type loadRootState struct {
	rootRole    *data.BaseRole
	checksummer data.ChecksumValidator
	gun         string
	certStore   trustmanager.X509Store
}

// Input takes a repo, some content, and a min version - if the content validates, it sets the
// metadata on the repo
func (s loadRootState) load(repo *Repo, roleName string, content []byte, minVersion int) error {
	if roleName != data.CanonicalRootRole {
		return ErrInvalidInputForBuilderState{expectedRoleType: data.CanonicalRootRole}
	}

	signedObj, err := bytesToSigned(content, data.CanonicalRootRole, s.checksummer)
	if err != nil {
		return err
	}

	if err := s.verifyPinnedTrust(signedObj); err != nil {
		return err
	}

	// verify that the metadata structure is correct
	signedRoot, err := data.RootFromSigned(signedObj)
	if err != nil {
		return err
	}

	// validate that the signatures for the root are consistent with its own definitions
	if err := signed.Verify(signedObj, signedRoot.GetRole(data.CanonicalRootRole), minVersion); err != nil {
		return err
	}

	repo.SetRoot(signedRoot)
	return nil
}

// validate against old keys or pinned trust certs
func (s loadRootState) verifyPinnedTrust(signedObj *data.Signed) error {
	if s.rootRole == nil {
		// TODO: certs.ValidateRoot should only check the trust pinning - we will
		// validate that the root is self-consistent with itself later
		// it also calls RootToSigned, so there are some inefficiencies here
		if err := certs.ValidateRoot(s.certStore, signedObj, s.gun); err != nil {
			logrus.Debug("TUF repo builder: root failed validation against trust certificates")
			return err
		}
	} else {
		// verify with existing keys rather than trust pinning
		if err := signed.VerifySignatures(signedObj, *s.rootRole); err != nil {
			logrus.Debug("TUF repo builder: root failed validation against previous root keys")
			return err
		}
	}
	return nil
}

// ---- load timestamp state ----

type loadTimestampState struct {
	role data.BaseRole
}

func (s loadTimestampState) load(repo *Repo, roleName string, content []byte, minVersion int) error {
	if roleName != data.CanonicalTimestampRole {
		return ErrInvalidInputForBuilderState{expectedRoleType: data.CanonicalTimestampRole}
	}

	signedObj, err := bytesToSigned(content, data.CanonicalTimestampRole, nil)
	if err != nil {
		return err
	}

	// verify signature, version, and expiry
	if err := signed.Verify(signedObj, s.role, minVersion); err != nil {
		return err
	}

	signedTimestamp, err := data.TimestampFromSigned(signedObj)
	if err != nil {
		return err
	}

	repo.SetTimestamp(signedTimestamp)
	return nil
}

// ---- load snapshot state ----

type loadSnapshotState struct {
	role        data.BaseRole
	checksummer data.ChecksumValidator
	loadedRoot  []byte
}

func (s loadSnapshotState) load(repo *Repo, roleName string, content []byte, minVersion int) error {
	if roleName != data.CanonicalSnapshotRole {
		return ErrInvalidInputForBuilderState{expectedRoleType: data.CanonicalSnapshotRole}
	}

	signedObj, err := bytesToSigned(content, data.CanonicalSnapshotRole, s.checksummer)
	if err != nil {
		return err
	}

	// verify signature, version, and expiry
	if err := signed.Verify(signedObj, s.role, minVersion); err != nil {
		return err
	}

	signedSnapshot, err := data.SnapshotFromSigned(signedObj)
	if err != nil {
		return err
	}

	// validate the root now that we have the snapshot
	checksum := signedSnapshot.Signed.Meta[data.CanonicalRootRole]
	if err := checksum.ValidateChecksum(s.loadedRoot, data.CanonicalRootRole); err != nil {
		return err
	}

	repo.SetSnapshot(signedSnapshot)
	return nil
}

// ---- load targets state ----

type loadTargetsState struct {
	role        data.BaseRole
	checksummer data.ChecksumValidator
}

func (s loadTargetsState) load(repo *Repo, roleName string, content []byte, minVersion int) error {
	if roleName != data.CanonicalTargetsRole {
		return ErrInvalidInputForBuilderState{expectedRoleType: data.CanonicalTargetsRole}
	}

	signedObj, err := bytesToSigned(content, data.CanonicalTargetsRole, s.checksummer)
	if err != nil {
		return err
	}

	// verify signature, version, and expiry
	if err := signed.Verify(signedObj, s.role, minVersion); err != nil {
		return err
	}

	signedTargets, err := data.TargetsFromSigned(signedObj, data.CanonicalTargetsRole)
	if err != nil {
		return err
	}

	repo.SetTargets(data.CanonicalTargetsRole, signedTargets)
	return nil
}

// ---- load delegation state ----

type loadDelegationState struct {
	targetsTree *data.SignedTargets
	checksummer data.ChecksumValidator
}

func (s loadDelegationState) load(repo *Repo, roleName string, content []byte, minVersion int) error {
	if !data.IsDelegation(roleName) {
		return ErrInvalidInputForBuilderState{expectedRoleType: "delegation role"}
	}

	// TODO: GetDelegationRole from the tree instead of the repo
	delegationRole, err := repo.GetDelegationRole(roleName)
	if err != nil {
		return err
	}

	signedObj, err := bytesToSigned(content, roleName, s.checksummer)
	if err != nil {
		return err
	}

	// verify signature, version, and expiry
	if err := signed.Verify(signedObj, delegationRole.BaseRole, minVersion); err != nil {
		return err
	}

	signedTargets, err := data.TargetsFromSigned(signedObj, roleName)
	if err != nil {
		return err
	}

	repo.SetTargets(roleName, signedTargets)
	return nil
}

// ---- build finished state ----

type buildingDoneState struct{}

// we cannot accept any more input
func (s buildingDoneState) load(repo *Repo, roleName string, content []byte, minVersion int) error {
	return ErrBuildDone{}
}
