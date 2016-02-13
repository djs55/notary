package tufv2

import "github.com/docker/notary/tuf/data"

// GetExpectedHashes expected hash metadata - to be used for getting hashes for
// one specific role, and should be bound to a closure
type GetExpectedHashes func() (*FileMeta, error)

// Visitor is something that can mutate a repo
type Visitor interface {
	VisitRoot(s *data.SignedRoot, getHashes GetExpectedHashes) error
	VisitTimestamp(r BaseRole, s *data.SignedTimestamp) error
	VisitSnapshot(r BaseRole, s *data.SignedSnapshot, getHashes GetExpectedHashes) error
	VisitTargets(r TargetRole, getHashes GetExpectedHashes) error
}

// ErrRestartWalk is an error that is returned that will cause the Walk function to start again
type ErrRestartWalk struct{}

func (err ErrRestartWalk) Error() string { return "walk again" }

// Walk walks the repo from root -> timestamp -> snapshot -> targets -> DFS delegations
// Walk does not account for malicious or buggy Visitors
func (tr *Repo) Walk(v Visitor) error {
	return tr.walk(v, []func(Visitor) error{
		tr.walkRoot,
		tr.walkTimestamp,
		tr.walkSnapshot,
		tr.walkTargets,
	})
}

// SignWalk walks the repo for signing
func (tr *Repo) SignWalk(v Visitor) error {
	return tr.walk(v, []func(Visitor) error{
		tr.walkRoot,
		tr.walkTargets,
		tr.walkSnapshot,
		tr.walkTimestamp,
	})
}

func (tr *Repo) walk(v Visitor, order []func(Visitor) error) (err error) {
	for ok := false; ok || err == nil; _, ok = err.(ErrRestartWalk) {
		for _, walkStep := range order {
			if err = walkStep(v); err != nil {
				break
			}
		}
	}
	return err
}

func (tr *Repo) getHashesClosure(role string) GetExpectedHashes {
	return func() (*data.FileMeta, error) {
		switch role {
		case data.CanonicalSnapshotRole:
			if tr.Timestamp == nil {
				return ErrNotLoaded{role: data.CanonicalTimestampRole}
			}
			return tr.Timestamp.GetMeta(role)
		default:
			if tr.Snapshot == nil {
				return ErrNotLoaded{role: data.CanonicalSnapshotRole}
			}
			return tr.Snapshot.GetMeta(role)
		}
	}
}

// Hits the root metadata, whether or not there is an expected hash for it
func (tr *Repo) walkRoot(v Visitor) error {
	return v.VisitRoot(tr.Root, getHashesClosure(data.CanonicalRootRole, tr.Snapshot))
}

// hits the timestamp metadata, assumes that root has to be loaded at this point
func (tr *Repo) walkTimestamp(v Visitor) error {
	// visit the timetamp
	timestampRole, err := tr.Root.GetBaseRole(data.CanonicalTimestampRole)
	if err != nil {
		return err
	}
	return v.VisitTimestamp(timestampRole, tr.Timestamp)
}

// hits the snapshot metadata, assumes that root has to be loaded at this point
func (tr *Repo) walkSnapshot(v Visitor) error {
	snapshotRole, err := tr.Root.GetBaseRole(data.CanonicalSnapshotRole)
	if err != nil {
		return err
	}
	return v.VisitSnapshot(snapshotRole, tr.Snapshot, getHashesClosure(data.CanonicalSnapshotRole, tr.Timestamp))
}

func (tr *Repo) walkTargets(v Visitor) error {
	// get the base target role from root
	targetsBaseRole, err := tr.Root.GetBaseRole(data.CanonicalTargetsRole)
	if err != nil {
		return err
	}
	if tr.Targets == nil {
		tr.Targets = new(data.SignedTargets)
	}

	// build a delegation role for the top level targets and set it as the root
	// of the targets tree to visit
	toVisit := []data.DelegationRole{data.DelegationRole{
		BaseRole:   targetsBaseRole,
		Paths:      []string{""},
		TargetMeta: tr.Targets,
	}}

	for len(toVisit) > 0 {
		roleToVisit := toVisit[0]
		toVisit = toVisit[1:]

		if err = v.VisitTargets(roleToVisit, getHashesClosure(roleToVisit.Name, tr.Snapshot)); err != nil {
			return err
		}

		if roleToVisit.TargetMeta != nil {
			toVisit = append(roleToVisit.TargetMeta.GetRoles(), toVisit...)
		}
	}
	return nil
}
