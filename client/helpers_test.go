package client

import (
	"crypto/sha256"
	"encoding/json"
	"testing"

	"github.com/docker/notary/client/changelist"
	"github.com/docker/notary/tuf/data"
	"github.com/docker/notary/tuf/testutils"
	"github.com/stretchr/testify/require"
)

func TestApplyTargetsChange(t *testing.T) {
	repo, _, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)
	_, err = repo.InitTargets(data.CanonicalTargetsRole)
	require.NoError(t, err)
	hash := sha256.Sum256([]byte{})
	f := &data.FileMeta{
		Length: 1,
		Hashes: map[string][]byte{
			"sha256": hash[:],
		},
	}
	fjson, err := json.Marshal(f)
	require.NoError(t, err)

	addChange := &changelist.TufChange{
		Actn:       changelist.ActionCreate,
		Role:       changelist.ScopeTargets,
		ChangeType: "target",
		ChangePath: "latest",
		Data:       fjson,
	}
	err = applyTargetsChange(repo, addChange)
	require.NoError(t, err)
	require.NotNil(t, repo.Targets["targets"].Signed.Targets["latest"])

	removeChange := &changelist.TufChange{
		Actn:       changelist.ActionDelete,
		Role:       changelist.ScopeTargets,
		ChangeType: "target",
		ChangePath: "latest",
		Data:       nil,
	}
	err = applyTargetsChange(repo, removeChange)
	require.NoError(t, err)
	_, ok := repo.Targets["targets"].Signed.Targets["latest"]
	require.False(t, ok)
}

// Adding the same target twice doesn't actually add it.
func TestApplyAddTargetTwice(t *testing.T) {
	repo, _, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)
	_, err = repo.InitTargets(data.CanonicalTargetsRole)
	require.NoError(t, err)
	hash := sha256.Sum256([]byte{})
	f := &data.FileMeta{
		Length: 1,
		Hashes: map[string][]byte{
			"sha256": hash[:],
		},
	}
	fjson, err := json.Marshal(f)
	require.NoError(t, err)

	cl := changelist.NewMemChangelist()
	require.NoError(t, cl.Add(&changelist.TufChange{
		Actn:       changelist.ActionCreate,
		Role:       changelist.ScopeTargets,
		ChangeType: "target",
		ChangePath: "latest",
		Data:       fjson,
	}))
	require.NoError(t, cl.Add(&changelist.TufChange{
		Actn:       changelist.ActionCreate,
		Role:       changelist.ScopeTargets,
		ChangeType: "target",
		ChangePath: "latest",
		Data:       fjson,
	}))

	require.NoError(t, applyChangelist(repo, cl))
	require.Len(t, repo.Targets["targets"].Signed.Targets, 1)
	require.NotEmpty(t, repo.Targets["targets"].Signed.Targets["latest"])

	require.NoError(t, applyTargetsChange(repo, &changelist.TufChange{
		Actn:       changelist.ActionCreate,
		Role:       changelist.ScopeTargets,
		ChangeType: "target",
		ChangePath: "latest",
		Data:       fjson,
	}))
	require.Len(t, repo.Targets["targets"].Signed.Targets, 1)
	require.NotEmpty(t, repo.Targets["targets"].Signed.Targets["latest"])
}

func TestApplyChangelist(t *testing.T) {
	repo, _, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)
	_, err = repo.InitTargets(data.CanonicalTargetsRole)
	require.NoError(t, err)
	hash := sha256.Sum256([]byte{})
	f := &data.FileMeta{
		Length: 1,
		Hashes: map[string][]byte{
			"sha256": hash[:],
		},
	}
	fjson, err := json.Marshal(f)
	require.NoError(t, err)

	cl := changelist.NewMemChangelist()
	addChange := &changelist.TufChange{
		Actn:       changelist.ActionCreate,
		Role:       changelist.ScopeTargets,
		ChangeType: "target",
		ChangePath: "latest",
		Data:       fjson,
	}
	cl.Add(addChange)
	err = applyChangelist(repo, cl)
	require.NoError(t, err)
	require.NotNil(t, repo.Targets["targets"].Signed.Targets["latest"])

	cl.Clear("")

	removeChange := &changelist.TufChange{
		Actn:       changelist.ActionDelete,
		Role:       changelist.ScopeTargets,
		ChangeType: "target",
		ChangePath: "latest",
		Data:       nil,
	}
	cl.Add(removeChange)
	err = applyChangelist(repo, cl)
	require.NoError(t, err)
	_, ok := repo.Targets["targets"].Signed.Targets["latest"]
	require.False(t, ok)
}

func TestApplyChangelistMulti(t *testing.T) {
	repo, _, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)
	_, err = repo.InitTargets(data.CanonicalTargetsRole)
	require.NoError(t, err)
	hash := sha256.Sum256([]byte{})
	f := &data.FileMeta{
		Length: 1,
		Hashes: map[string][]byte{
			"sha256": hash[:],
		},
	}
	fjson, err := json.Marshal(f)
	require.NoError(t, err)

	cl := changelist.NewMemChangelist()
	addChange := &changelist.TufChange{
		Actn:       changelist.ActionCreate,
		Role:       changelist.ScopeTargets,
		ChangeType: "target",
		ChangePath: "latest",
		Data:       fjson,
	}

	removeChange := &changelist.TufChange{
		Actn:       changelist.ActionDelete,
		Role:       changelist.ScopeTargets,
		ChangeType: "target",
		ChangePath: "latest",
		Data:       nil,
	}

	cl.Add(addChange)
	cl.Add(removeChange)

	err = applyChangelist(repo, cl)
	require.NoError(t, err)
	_, ok := repo.Targets["targets"].Signed.Targets["latest"]
	require.False(t, ok)
}

func TestApplyTargetsDelegationCreateDelete(t *testing.T) {
	repo, cs, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)

	newKey, err := cs.Create("targets/level1", data.ED25519Key)
	require.NoError(t, err)

	// create delegation
	kl := data.KeyList{newKey}
	td := &changelist.TufDelegation{
		NewThreshold: 1,
		AddKeys:      kl,
		AddPaths:     []string{"level1"},
	}

	tdJSON, err := json.Marshal(td)
	require.NoError(t, err)

	ch := changelist.NewTufChange(
		changelist.ActionCreate,
		"targets/level1",
		changelist.TypeTargetsDelegation,
		"",
		tdJSON,
	)

	err = applyTargetsChange(repo, ch)
	require.NoError(t, err)

	tgts := repo.Targets[data.CanonicalTargetsRole]
	require.Len(t, tgts.Signed.Delegations.Roles, 1)
	require.Len(t, tgts.Signed.Delegations.Keys, 1)

	_, ok := tgts.Signed.Delegations.Keys[newKey.ID()]
	require.True(t, ok)

	role := tgts.Signed.Delegations.Roles[0]
	require.Len(t, role.KeyIDs, 1)
	require.Equal(t, newKey.ID(), role.KeyIDs[0])
	require.Equal(t, "targets/level1", role.Name)
	require.Equal(t, "level1", role.Paths[0])

	// delete delegation
	td = &changelist.TufDelegation{
		RemoveKeys: []string{newKey.ID()},
	}

	tdJSON, err = json.Marshal(td)
	require.NoError(t, err)
	ch = changelist.NewTufChange(
		changelist.ActionDelete,
		"targets/level1",
		changelist.TypeTargetsDelegation,
		"",
		tdJSON,
	)

	err = applyTargetsChange(repo, ch)
	require.NoError(t, err)

	require.Len(t, tgts.Signed.Delegations.Roles, 0)
	require.Len(t, tgts.Signed.Delegations.Keys, 0)
}

func TestApplyTargetsDelegationCreate2SharedKey(t *testing.T) {
	repo, cs, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)

	newKey, err := cs.Create("targets/level1", data.ED25519Key)
	require.NoError(t, err)

	// create first delegation
	kl := data.KeyList{newKey}
	td := &changelist.TufDelegation{
		NewThreshold: 1,
		AddKeys:      kl,
		AddPaths:     []string{"level1"},
	}

	tdJSON, err := json.Marshal(td)
	require.NoError(t, err)

	ch := changelist.NewTufChange(
		changelist.ActionCreate,
		"targets/level1",
		changelist.TypeTargetsDelegation,
		"",
		tdJSON,
	)

	err = applyTargetsChange(repo, ch)
	require.NoError(t, err)

	// create second delegation
	kl = data.KeyList{newKey}
	td = &changelist.TufDelegation{
		NewThreshold: 1,
		AddKeys:      kl,
		AddPaths:     []string{"level2"},
	}

	tdJSON, err = json.Marshal(td)
	require.NoError(t, err)

	ch = changelist.NewTufChange(
		changelist.ActionCreate,
		"targets/level2",
		changelist.TypeTargetsDelegation,
		"",
		tdJSON,
	)

	err = applyTargetsChange(repo, ch)
	require.NoError(t, err)

	tgts := repo.Targets[data.CanonicalTargetsRole]
	require.Len(t, tgts.Signed.Delegations.Roles, 2)
	require.Len(t, tgts.Signed.Delegations.Keys, 1)

	role1 := tgts.Signed.Delegations.Roles[0]
	require.Len(t, role1.KeyIDs, 1)
	require.Equal(t, newKey.ID(), role1.KeyIDs[0])
	require.Equal(t, "targets/level1", role1.Name)
	require.Equal(t, "level1", role1.Paths[0])

	role2 := tgts.Signed.Delegations.Roles[1]
	require.Len(t, role2.KeyIDs, 1)
	require.Equal(t, newKey.ID(), role2.KeyIDs[0])
	require.Equal(t, "targets/level2", role2.Name)
	require.Equal(t, "level2", role2.Paths[0])

	// delete one delegation, ensure shared key remains
	td = &changelist.TufDelegation{
		RemoveKeys: []string{newKey.ID()},
	}
	tdJSON, err = json.Marshal(td)
	require.NoError(t, err)
	ch = changelist.NewTufChange(
		changelist.ActionDelete,
		"targets/level1",
		changelist.TypeTargetsDelegation,
		"",
		tdJSON,
	)

	err = applyTargetsChange(repo, ch)
	require.NoError(t, err)

	require.Len(t, tgts.Signed.Delegations.Roles, 1)
	require.Len(t, tgts.Signed.Delegations.Keys, 1)

	// delete other delegation, ensure key cleaned up
	ch = changelist.NewTufChange(
		changelist.ActionDelete,
		"targets/level2",
		changelist.TypeTargetsDelegation,
		"",
		tdJSON,
	)

	err = applyTargetsChange(repo, ch)
	require.NoError(t, err)

	require.Len(t, tgts.Signed.Delegations.Roles, 0)
	require.Len(t, tgts.Signed.Delegations.Keys, 0)
}

func TestApplyTargetsDelegationCreateEdit(t *testing.T) {
	repo, cs, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)

	newKey, err := cs.Create("targets/level1", data.ED25519Key)
	require.NoError(t, err)

	// create delegation
	kl := data.KeyList{newKey}
	td := &changelist.TufDelegation{
		NewThreshold: 1,
		AddKeys:      kl,
		AddPaths:     []string{"level1"},
	}

	tdJSON, err := json.Marshal(td)
	require.NoError(t, err)

	ch := changelist.NewTufChange(
		changelist.ActionCreate,
		"targets/level1",
		changelist.TypeTargetsDelegation,
		"",
		tdJSON,
	)

	err = applyTargetsChange(repo, ch)
	require.NoError(t, err)

	// edit delegation
	newKey2, err := cs.Create("targets/level1", data.ED25519Key)
	require.NoError(t, err)

	kl = data.KeyList{newKey2}
	td = &changelist.TufDelegation{
		NewThreshold: 1,
		AddKeys:      kl,
		RemoveKeys:   []string{newKey.ID()},
	}

	tdJSON, err = json.Marshal(td)
	require.NoError(t, err)

	ch = changelist.NewTufChange(
		changelist.ActionUpdate,
		"targets/level1",
		changelist.TypeTargetsDelegation,
		"",
		tdJSON,
	)

	err = applyTargetsChange(repo, ch)
	require.NoError(t, err)

	tgts := repo.Targets[data.CanonicalTargetsRole]
	require.Len(t, tgts.Signed.Delegations.Roles, 1)
	require.Len(t, tgts.Signed.Delegations.Keys, 1)

	_, ok := tgts.Signed.Delegations.Keys[newKey2.ID()]
	require.True(t, ok)

	role := tgts.Signed.Delegations.Roles[0]
	require.Len(t, role.KeyIDs, 1)
	require.Equal(t, newKey2.ID(), role.KeyIDs[0])
	require.Equal(t, "targets/level1", role.Name)
	require.Equal(t, "level1", role.Paths[0])
}

func TestApplyTargetsDelegationEditNonExisting(t *testing.T) {
	repo, cs, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)

	newKey, err := cs.Create("targets/level1", data.ED25519Key)
	require.NoError(t, err)

	// create delegation
	kl := data.KeyList{newKey}
	td := &changelist.TufDelegation{
		NewThreshold: 1,
		AddKeys:      kl,
		AddPaths:     []string{"level1"},
	}

	tdJSON, err := json.Marshal(td)
	require.NoError(t, err)

	ch := changelist.NewTufChange(
		changelist.ActionUpdate,
		"targets/level1",
		changelist.TypeTargetsDelegation,
		"",
		tdJSON,
	)

	err = applyTargetsChange(repo, ch)
	require.Error(t, err)
	require.IsType(t, data.ErrInvalidRole{}, err)
}

func TestApplyTargetsDelegationCreateAlreadyExisting(t *testing.T) {
	repo, cs, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)

	newKey, err := cs.Create("targets/level1", data.ED25519Key)
	require.NoError(t, err)

	// create delegation
	kl := data.KeyList{newKey}
	td := &changelist.TufDelegation{
		NewThreshold: 1,
		AddKeys:      kl,
		AddPaths:     []string{"level1"},
	}

	tdJSON, err := json.Marshal(td)
	require.NoError(t, err)

	ch := changelist.NewTufChange(
		changelist.ActionCreate,
		"targets/level1",
		changelist.TypeTargetsDelegation,
		"",
		tdJSON,
	)

	err = applyTargetsChange(repo, ch)
	require.NoError(t, err)
	// we have sufficient checks elsewhere we don't need to confirm that
	// creating fresh works here via more requires.

	extraKey, err := cs.Create("targets/level1", data.ED25519Key)
	require.NoError(t, err)

	// create delegation
	kl = data.KeyList{extraKey}
	td = &changelist.TufDelegation{
		NewThreshold: 1,
		AddKeys:      kl,
		AddPaths:     []string{"level1"},
	}

	tdJSON, err = json.Marshal(td)
	require.NoError(t, err)

	ch = changelist.NewTufChange(
		changelist.ActionCreate,
		"targets/level1",
		changelist.TypeTargetsDelegation,
		"",
		tdJSON,
	)

	// when attempting to create the same role again, check that we added a key
	err = applyTargetsChange(repo, ch)
	require.NoError(t, err)
	delegation, err := repo.GetDelegationRole("targets/level1")
	require.NoError(t, err)
	require.Contains(t, delegation.Paths, "level1")
	require.Equal(t, len(delegation.ListKeyIDs()), 2)
}

func TestApplyTargetsDelegationAlreadyExistingMergePaths(t *testing.T) {
	repo, cs, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)

	newKey, err := cs.Create("targets/level1", data.ED25519Key)
	require.NoError(t, err)

	// create delegation
	kl := data.KeyList{newKey}
	td := &changelist.TufDelegation{
		NewThreshold: 1,
		AddKeys:      kl,
		AddPaths:     []string{"level1"},
	}

	tdJSON, err := json.Marshal(td)
	require.NoError(t, err)

	ch := changelist.NewTufChange(
		changelist.ActionCreate,
		"targets/level1",
		changelist.TypeTargetsDelegation,
		"",
		tdJSON,
	)

	err = applyTargetsChange(repo, ch)
	require.NoError(t, err)
	// we have sufficient checks elsewhere we don't need to confirm that
	// creating fresh works here via more requires.

	// Use different path for this changelist
	td.AddPaths = []string{"level2"}

	tdJSON, err = json.Marshal(td)
	require.NoError(t, err)

	ch = changelist.NewTufChange(
		changelist.ActionCreate,
		"targets/level1",
		changelist.TypeTargetsDelegation,
		"",
		tdJSON,
	)

	// when attempting to create the same role again, check that we
	// merged with previous details
	err = applyTargetsChange(repo, ch)
	require.NoError(t, err)
	delegation, err := repo.GetDelegationRole("targets/level1")
	require.NoError(t, err)
	// Assert we have both paths
	require.Contains(t, delegation.Paths, "level2")
	require.Contains(t, delegation.Paths, "level1")
}

func TestApplyTargetsDelegationInvalidRole(t *testing.T) {
	repo, cs, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)

	newKey, err := cs.Create("targets/level1", data.ED25519Key)
	require.NoError(t, err)

	// create delegation
	kl := data.KeyList{newKey}
	td := &changelist.TufDelegation{
		NewThreshold: 1,
		AddKeys:      kl,
		AddPaths:     []string{"level1"},
	}

	tdJSON, err := json.Marshal(td)
	require.NoError(t, err)

	ch := changelist.NewTufChange(
		changelist.ActionCreate,
		"bad role",
		changelist.TypeTargetsDelegation,
		"",
		tdJSON,
	)

	err = applyTargetsChange(repo, ch)
	require.Error(t, err)
}

func TestApplyTargetsDelegationInvalidJSONContent(t *testing.T) {
	repo, cs, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)

	newKey, err := cs.Create("targets/level1", data.ED25519Key)
	require.NoError(t, err)

	// create delegation
	kl := data.KeyList{newKey}
	td := &changelist.TufDelegation{
		NewThreshold: 1,
		AddKeys:      kl,
		AddPaths:     []string{"level1"},
	}

	tdJSON, err := json.Marshal(td)
	require.NoError(t, err)

	ch := changelist.NewTufChange(
		changelist.ActionCreate,
		"targets/level1",
		changelist.TypeTargetsDelegation,
		"",
		tdJSON[1:],
	)

	err = applyTargetsChange(repo, ch)
	require.Error(t, err)
}

func TestApplyTargetsDelegationInvalidAction(t *testing.T) {
	repo, _, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)

	ch := changelist.NewTufChange(
		"bad action",
		"targets/level1",
		changelist.TypeTargetsDelegation,
		"",
		nil,
	)

	err = applyTargetsChange(repo, ch)
	require.Error(t, err)
}

func TestApplyTargetsChangeInvalidType(t *testing.T) {
	repo, _, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)

	ch := changelist.NewTufChange(
		changelist.ActionCreate,
		"targets/level1",
		"badType",
		"",
		nil,
	)

	err = applyTargetsChange(repo, ch)
	require.Error(t, err)
}

func TestApplyTargetsDelegationCreate2Deep(t *testing.T) {
	repo, cs, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)

	newKey, err := cs.Create("targets/level1", data.ED25519Key)
	require.NoError(t, err)

	// create delegation
	kl := data.KeyList{newKey}
	td := &changelist.TufDelegation{
		NewThreshold: 1,
		AddKeys:      kl,
		AddPaths:     []string{"level1"},
	}

	tdJSON, err := json.Marshal(td)
	require.NoError(t, err)

	ch := changelist.NewTufChange(
		changelist.ActionCreate,
		"targets/level1",
		changelist.TypeTargetsDelegation,
		"",
		tdJSON,
	)

	err = applyTargetsChange(repo, ch)
	require.NoError(t, err)

	tgts := repo.Targets[data.CanonicalTargetsRole]
	require.Len(t, tgts.Signed.Delegations.Roles, 1)
	require.Len(t, tgts.Signed.Delegations.Keys, 1)

	_, ok := tgts.Signed.Delegations.Keys[newKey.ID()]
	require.True(t, ok)

	role := tgts.Signed.Delegations.Roles[0]
	require.Len(t, role.KeyIDs, 1)
	require.Equal(t, newKey.ID(), role.KeyIDs[0])
	require.Equal(t, "targets/level1", role.Name)
	require.Equal(t, "level1", role.Paths[0])

	// init delegations targets file. This would be done as part of a publish
	// operation
	repo.InitTargets("targets/level1")

	td = &changelist.TufDelegation{
		NewThreshold: 1,
		AddKeys:      kl,
		AddPaths:     []string{"level1/level2"},
	}

	tdJSON, err = json.Marshal(td)
	require.NoError(t, err)

	ch = changelist.NewTufChange(
		changelist.ActionCreate,
		"targets/level1/level2",
		changelist.TypeTargetsDelegation,
		"",
		tdJSON,
	)

	err = applyTargetsChange(repo, ch)
	require.NoError(t, err)

	tgts = repo.Targets["targets/level1"]
	require.Len(t, tgts.Signed.Delegations.Roles, 1)
	require.Len(t, tgts.Signed.Delegations.Keys, 1)

	_, ok = tgts.Signed.Delegations.Keys[newKey.ID()]
	require.True(t, ok)

	role = tgts.Signed.Delegations.Roles[0]
	require.Len(t, role.KeyIDs, 1)
	require.Equal(t, newKey.ID(), role.KeyIDs[0])
	require.Equal(t, "targets/level1/level2", role.Name)
	require.Equal(t, "level1/level2", role.Paths[0])
}

// Applying a delegation whose parent doesn't exist fails.
func TestApplyTargetsDelegationParentDoesntExist(t *testing.T) {
	repo, cs, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)

	// make sure a key exists for the previous level, so it's not a missing
	// key error, but we don't care about this key
	_, err = cs.Create("targets/level1", data.ED25519Key)
	require.NoError(t, err)

	newKey, err := cs.Create("targets/level1/level2", data.ED25519Key)
	require.NoError(t, err)

	// create delegation
	kl := data.KeyList{newKey}
	td := &changelist.TufDelegation{
		NewThreshold: 1,
		AddKeys:      kl,
	}

	tdJSON, err := json.Marshal(td)
	require.NoError(t, err)

	ch := changelist.NewTufChange(
		changelist.ActionCreate,
		"targets/level1/level2",
		changelist.TypeTargetsDelegation,
		"",
		tdJSON,
	)

	err = applyTargetsChange(repo, ch)
	require.Error(t, err)
	require.IsType(t, data.ErrInvalidRole{}, err)
}

// If there is no delegation target, ApplyTargets creates it
func TestApplyChangelistCreatesDelegation(t *testing.T) {
	repo, cs, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)

	newKey, err := cs.Create("targets/level1", data.ED25519Key)
	require.NoError(t, err)

	err = repo.UpdateDelegationKeys("targets/level1", []data.PublicKey{newKey}, []string{}, 1)
	require.NoError(t, err)
	err = repo.UpdateDelegationPaths("targets/level1", []string{""}, []string{}, false)
	delete(repo.Targets, "targets/level1")

	hash := sha256.Sum256([]byte{})
	f := &data.FileMeta{
		Length: 1,
		Hashes: map[string][]byte{
			"sha256": hash[:],
		},
	}
	fjson, err := json.Marshal(f)
	require.NoError(t, err)

	cl := changelist.NewMemChangelist()
	require.NoError(t, cl.Add(&changelist.TufChange{
		Actn:       changelist.ActionCreate,
		Role:       "targets/level1",
		ChangeType: "target",
		ChangePath: "latest",
		Data:       fjson,
	}))

	require.NoError(t, applyChangelist(repo, cl))
	_, ok := repo.Targets["targets/level1"]
	require.True(t, ok, "Failed to create the delegation target")
	_, ok = repo.Targets["targets/level1"].Signed.Targets["latest"]
	require.True(t, ok, "Failed to write change to delegation target")
}

// Each change applies only to the role specified
func TestApplyChangelistTargetsToMultipleRoles(t *testing.T) {
	repo, cs, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)

	newKey, err := cs.Create("targets/level1", data.ED25519Key)
	require.NoError(t, err)

	err = repo.UpdateDelegationKeys("targets/level1", []data.PublicKey{newKey}, []string{}, 1)
	require.NoError(t, err)
	err = repo.UpdateDelegationPaths("targets/level1", []string{""}, []string{}, false)
	require.NoError(t, err)

	err = repo.UpdateDelegationKeys("targets/level2", []data.PublicKey{newKey}, []string{}, 1)
	require.NoError(t, err)
	err = repo.UpdateDelegationPaths("targets/level2", []string{""}, []string{}, false)
	require.NoError(t, err)

	hash := sha256.Sum256([]byte{})
	f := &data.FileMeta{
		Length: 1,
		Hashes: map[string][]byte{
			"sha256": hash[:],
		},
	}
	fjson, err := json.Marshal(f)
	require.NoError(t, err)

	cl := changelist.NewMemChangelist()
	require.NoError(t, cl.Add(&changelist.TufChange{
		Actn:       changelist.ActionCreate,
		Role:       "targets/level1",
		ChangeType: "target",
		ChangePath: "latest",
		Data:       fjson,
	}))
	require.NoError(t, cl.Add(&changelist.TufChange{
		Actn:       changelist.ActionDelete,
		Role:       "targets/level2",
		ChangeType: "target",
		ChangePath: "latest",
		Data:       nil,
	}))

	require.NoError(t, applyChangelist(repo, cl))
	_, ok := repo.Targets["targets/level1"].Signed.Targets["latest"]
	require.True(t, ok)
	_, ok = repo.Targets["targets/level2"]
	require.False(t, ok, "no change to targets/level2, so metadata not created")
}

// ApplyTargets fails when adding or deleting a change to a nonexistent delegation
func TestApplyChangelistTargetsFailsNonexistentRole(t *testing.T) {
	repo, _, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)

	hash := sha256.Sum256([]byte{})
	f := &data.FileMeta{
		Length: 1,
		Hashes: map[string][]byte{
			"sha256": hash[:],
		},
	}
	fjson, err := json.Marshal(f)
	require.NoError(t, err)

	cl := changelist.NewMemChangelist()
	require.NoError(t, cl.Add(&changelist.TufChange{
		Actn:       changelist.ActionCreate,
		Role:       "targets/level1/level2/level3/level4",
		ChangeType: "target",
		ChangePath: "latest",
		Data:       fjson,
	}))
	err = applyChangelist(repo, cl)
	require.Error(t, err)
	require.IsType(t, data.ErrInvalidRole{}, err)

	// now try a delete and assert the same error
	cl = changelist.NewMemChangelist()
	require.NoError(t, cl.Add(&changelist.TufChange{
		Actn:       changelist.ActionDelete,
		Role:       "targets/level1/level2/level3/level4",
		ChangeType: "target",
		ChangePath: "latest",
		Data:       nil,
	}))

	err = applyChangelist(repo, cl)
	require.Error(t, err)
	require.IsType(t, data.ErrInvalidRole{}, err)
}

// changeTargetMeta fails with ErrInvalidRole if role is invalid
func TestChangeTargetMetaFailsInvalidRole(t *testing.T) {
	repo, _, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)

	hash := sha256.Sum256([]byte{})
	f := &data.FileMeta{
		Length: 1,
		Hashes: map[string][]byte{
			"sha256": hash[:],
		},
	}
	fjson, err := json.Marshal(f)
	require.NoError(t, err)

	err = changeTargetMeta(repo, &changelist.TufChange{
		Actn:       changelist.ActionCreate,
		Role:       "ruhroh",
		ChangeType: "target",
		ChangePath: "latest",
		Data:       fjson,
	})
	require.Error(t, err)
	require.IsType(t, data.ErrInvalidRole{}, err)
}

// If applying a change fails due to a prefix error, changeTargetMeta fails outright
func TestChangeTargetMetaFailsIfPrefixError(t *testing.T) {
	repo, cs, err := testutils.EmptyRepo("docker.com/notary")
	require.NoError(t, err)

	newKey, err := cs.Create("targets/level1", data.ED25519Key)
	require.NoError(t, err)

	err = repo.UpdateDelegationKeys("targets/level1", []data.PublicKey{newKey}, []string{}, 1)
	require.NoError(t, err)
	err = repo.UpdateDelegationPaths("targets/level1", []string{"pathprefix"}, []string{}, false)
	require.NoError(t, err)

	hash := sha256.Sum256([]byte{})
	f := &data.FileMeta{
		Length: 1,
		Hashes: map[string][]byte{
			"sha256": hash[:],
		},
	}
	fjson, err := json.Marshal(f)
	require.NoError(t, err)

	err = changeTargetMeta(repo, &changelist.TufChange{
		Actn:       changelist.ActionCreate,
		Role:       "targets/level1",
		ChangeType: "target",
		ChangePath: "notPathPrefix",
		Data:       fjson,
	})
	require.Error(t, err)

	// no target in targets or targets/latest
	require.Empty(t, repo.Targets[data.CanonicalTargetsRole].Signed.Targets)
	require.Empty(t, repo.Targets["targets/level1"].Signed.Targets)
}
