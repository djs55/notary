package tuf

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Sirupsen/logrus"
	"github.com/docker/notary/tuf/data"
)

type ErrBadState struct {
	state BuildState
}

func (err ErrBadState) Error() string {
	return fmt.Sprintf("RepoBuilder is in invalid state: %d", err.state)
}

type BuildState int

const (
	StateLoadRoot BuildState = iota
	StateLoadTimestamp
	StateLoadSnapshot
	StateLoadTargets
	StateLoadDelegations
	StateComplete
	StateFailed
)

type RepoBuilder struct {
	repo  *Repo
	state BuildState
}

func NewRepoBuilder(role *data.Role, meta data.FileMeta) *RepoBuilder {
	return &RepoBuilder{
		repo:  NewRepo(),
		state: StateLoadRoot,
	}
}

func (rb *RepoBuilder) Set(content []byte) error {
	switch rb.state {
	case StateComplete, StateFailed:
		return nil
	case StateLoadRoot:
		parsed, err := rb.verifyRoot(*role, content)
		if err != nil {
			return err
		}
		if err := rb.setRoot(parsed); err != nil {
			return err
		}
		rb.state = StateLoadTimestamp

	case StateLoadTimestamp:
		tsRole, err := repo.GetBaseRole("timestamp")
		parsed, err := rb.verifyTimestamp(*role, content)
		if err != nil {
			return err
		}
		rb.setTimestamp(parsed)
		rb.state = StateLoadSnapshot

	case StateLoadSnapshot:
		parsed, err := rb.verifySnapshot(*role, content)
		if err != nil {
			return err
		}
		rb.setSnapshot(parsed)
		rb.state = StateLoadTargets

	case StateLoadTargets:
		parsed, err := rb.verifyTargets(*role, content)
		if err != nil {
			return err
		}
		rb.setTargets(parsed)
		rb.state = StateLoadDelegations

	case StateLoadDelegations:
		parsed, err := rb.verifyTargets(*role, content)
		if err != nil {
			return err
		}
		rb.setDelegation(role, parsed)
		// once we reach this state, it's difficult to be certain we're complete.
		// We set StateComplete in the rb.Repo() method as the builder should no
		// longer be allowed to modify the repo once it has been retrieved.

	default:
		// should never get here but let's create a good error
		// if somebody manages to do something they shouldn't
		badState := rb.state
		rb.state = StateFailed
		return ErrBadState{state: badState}
	}
	return nil
}

// Repo sets the state of the builder to StateComplete and returns the
// repo field. Once the repo has been retrieved from the builder, the
// builder must refuse to modify it further, any building is considered
// complete.
func (rb *RepoBuilder) Repo() (*Repo, error) {
	// once a repo has been extracted, this builder will no longer
	// modify that repo. Set it to StateComplete if it was anything
	// other than StateFailed
	if rb.state != StateFailed {
		rb.state = StateComplete
	}
	return rb.repo
}

func (rb *RepoBuilder) RetryBuild() *RepoBuilder {

}

func (rb *RepoBuilder) verifyRoot(role data.Role, content []byte) (*data.SignedRoot, error) {
	parsed := &data.SignedRoot{}
	err := json.Unmarshal(content, parsed)
	return parsed, err
}

func (rb *RepoBuilder) verifyTimestamp(role data.Role, content []byte) (*data.SignedTimestamp, error) {
	parsed := &data.SignedTimestamp{}
	err := json.Unmarshal(content, parsed)
	return parsed, err
}

func (rb *RepoBuilder) verifySnapshot(role data.Role, content []byte) (*data.SignedSnapshot, error) {
	parsed := &data.SignedSnapshot{}
	err := json.Unmarshal(content, parsed)
	return parsed, err
}

func (rb *RepoBuilder) verifyTargets(role data.Role, content []byte) (*data.SignedTargets, error) {
	parsed := &data.SignedTargets{}
	err := json.Unmarshal(content, parsed)
	return parsed, err
}

func (rb *RepoBuilder) setRoot(parsed *data.SignedRoot) error {
	for _, key := range parsed.Signed.Keys {
		logrus.Debug("Adding key ", key.ID())
		rb.repo.keysDB.AddKey(key)
	}
	for roleName, role := range parsed.Signed.Roles {
		logrus.Debugf("Adding role %s with keys %s", roleName, strings.Join(role.KeyIDs, ","))
		baseRole, err := data.NewRole(
			roleName,
			role.Threshold,
			role.KeyIDs,
			nil,
			nil,
		)
		if err != nil {
			return err
		}
		err = rb.repo.keysDB.AddRole(baseRole)
		if err != nil {
			return err
		}
	}
	rb.repo.root = parsed
	return nil
}

func (rb *RepoBuilder) setTimestamp(parsed *data.SignedTimestamp) {
	rb.repo.timestamp = parsed
}

func (rb *RepoBuilder) setSnapshot(parsed *data.SignedSnapshot) {
	rb.repo.snapshot = parsed
}

func (rb *RepoBuilder) setTargets(parsed *data.SignedTargets) {
	rb.updateDelegations(parsed)
	rb.repo.targets["targets"] = parsed
}

func (rb *RepoBuilder) setDelegation(role *data.Role, parsed *data.SignedTargets) {
	rb.updateDelegations(parsed)
	rb.repo.targets[role.Name] = parsed
}

// TODO: delete this when KeyDB gets purged
func (rb *RepoBuilder) updateDelegations(parsed *data.SignedTargets) {
	for _, k := range parsed.Signed.Delegations.Keys {
		rb.repo.keysDB.AddKey(k)
	}
	for _, r := range parsed.Signed.Delegations.Roles {
		rb.repo.keysDB.AddRole(r)
	}
}
