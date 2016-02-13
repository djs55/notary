package data

import (
	"errors"

	"github.com/docker/go/canonical/json"
)

// SignedTargets is a fully unpacked targets.json, or target delegation
// json file
type SignedTargets struct {
	Signatures []Signature
	Signed     Targets
	Dirty      bool
}

// Targets is the Signed components of a targets.json or delegation json file
type Targets struct {
	SignedCommon
	Targets     Files       `json:"targets"`
	Delegations Delegations `json:"delegations,omitempty"`
}

// NewTargets intiializes a new empty SignedTargets object
func NewTargets() *SignedTargets {
	return &SignedTargets{
		Signatures: make([]Signature, 0),
		Signed: Targets{
			SignedCommon: SignedCommon{
				Type:    TUFTypes["targets"],
				Version: 0,
				Expires: DefaultExpires("targets"),
			},
			Targets:     make(Files),
			Delegations: *NewDelegations(),
		},
		Dirty: true,
	}
}

// GetMeta attempts to find the targets entry for the path. It
// will return nil in the case of the target not being found.
func (t SignedTargets) GetMeta(path string) *FileMeta {
	for p, meta := range t.Signed.Targets {
		if p == path {
			return &meta
		}
	}
	return nil
}

// GetRoles returns DelgationRole objects for each of the roles defined in
// this targets metadata
func (t SignedTargets) GetRoles() []DelegationRole {
	var children []DelegationRole
	for _, roleObj := range t.Signed.Delegations.Roles {
		// Get all public keys for the base role from TUF metadata
		keyIDs := roleObj.KeyIDs
		pubKeys := make(map[string]PublicKey)
		for _, keyID := range keyIDs {
			pubKey, ok := t.Signed.Delegations.Keys[keyID]
			if ok {
				pubKeys[keyID] = pubKey
			}
		}

		if roleObj.TargetMeta == nil {
			roleObj.TargetMeta = new(SignedTargets)
		}

		children = append(children, DelegationRole{
			BaseRole: BaseRole{
				Name:      roleObj.Name,
				Keys:      pubKeys,
				Threshold: roleObj.Threshold,
			},
			Paths:      roleObj.Paths,
			TargetMeta: roleObj.TargetMeta,
		})
	}
	return children
}

// AddTarget adds or updates the meta for the given path
func (t *SignedTargets) AddTarget(path string, meta FileMeta) {
	t.Signed.Targets[path] = meta
	t.Dirty = true
}

// AddDelegation will add a new delegated role with the given keys,
// ensuring the keys either already exist, or are added to the map
// of delegation keys
func (t *SignedTargets) AddDelegation(role *Role, keys []*PublicKey) error {
	return errors.New("Not Implemented")
}

// ToSigned partially serializes a SignedTargets for further signing
func (t SignedTargets) ToSigned() (*Signed, error) {
	s, err := json.MarshalCanonical(t.Signed)
	if err != nil {
		return nil, err
	}
	signed := json.RawMessage{}
	err = signed.UnmarshalJSON(s)
	if err != nil {
		return nil, err
	}
	sigs := make([]Signature, len(t.Signatures))
	copy(sigs, t.Signatures)
	return &Signed{
		Signatures: sigs,
		Signed:     signed,
	}, nil
}

// TargetsFromSigned fully unpacks a Signed object into a SignedTargets
func TargetsFromSigned(s *Signed) (*SignedTargets, error) {
	t := Targets{}
	err := json.Unmarshal(s.Signed, &t)
	if err != nil {
		return nil, err
	}
	sigs := make([]Signature, len(s.Signatures))
	copy(sigs, s.Signatures)
	return &SignedTargets{
		Signatures: sigs,
		Signed:     t,
	}, nil
}
