package data

import "fmt"

// ErrInvalidMetadata is the error to be returned when metadata is invalid
type ErrInvalidMetadata struct {
	role string
	msg  string
}

func (e ErrInvalidMetadata) Error() string {
	return fmt.Sprintf("%s type metadata invalid: %s", e.role, e.msg)
}

// ErrMissingMeta - couldn't find the FileMeta object for the given name, or
// the FileMeta object contained no supported checksums
type ErrMissingMeta struct {
	name string
}

func (e ErrMissingMeta) Error() string {
	return fmt.Sprintf("no checksum for supported algorithms were provided for %s", e.name)
}

// ErrChecksumMismatch - a checksum failed verification
type ErrChecksumMismatch struct {
	hashAlgorithm string
	name          string
}

func (e ErrChecksumMismatch) Error() string {
	return fmt.Sprintf("%s checksum for %s did not match", e.hashAlgorithm, e.name)
}

// ErrFileTooBig is the error to be returned when the bytes for a particular
// file exceeds the max length as specified by a FileMeta
type ErrFileTooBig struct {
	name string
}

func (e ErrFileTooBig) Error() string {
	return fmt.Sprintf("%s exceeds the maximum specified size of %s bytes")
}
