// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package warp

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

// referenceFirstErr is an inlined snapshot of the historical
// wrappers.Errs behavior. It exists only here to lock in byte-for-byte
// (or rather error-identity) semantics after dropping the codec
// dependency.
type referenceFirstErr struct{ Err error }

func (e *referenceFirstErr) Add(errs ...error) {
	if e.Err == nil {
		for _, err := range errs {
			if err != nil {
				e.Err = err
				break
			}
		}
	}
}

func TestFirstErr_MatchesReferenceWrappersErrs(t *testing.T) {
	require := require.New(t)

	errA := errors.New("a")
	errB := errors.New("b")
	errC := errors.New("c")

	cases := [][]error{
		{},
		{nil},
		{nil, nil, nil},
		{errA},
		{nil, errA},
		{errA, errB},
		{nil, errA, nil, errB, errC},
		{errA, nil, errB},
	}

	for i, errs := range cases {
		var got firstErr
		var ref referenceFirstErr
		for _, e := range errs {
			got.add(e)
			ref.Add(e)
		}
		require.Equal(ref.Err, got.err, "case %d: identity mismatch (errs=%v)", i, errs)
		if ref.Err != nil {
			require.Same(ref.Err, got.err, "case %d: identity mismatch (errs=%v)", i, errs)
		}
	}
}

func TestFirstErr_SeededLikeSocketClose(t *testing.T) {
	// Mirrors the wrappers.Errs{Err: err} seeded pattern from
	// socket.Socket.Close — the seed wins even when subsequent Add
	// receives non-nil errors.
	require := require.New(t)

	seed := errors.New("seed")
	later := errors.New("later")

	var got firstErr
	got.err = seed
	got.add(later)
	got.add(nil)
	got.add(later)

	var ref referenceFirstErr
	ref.Err = seed
	ref.Add(later)
	ref.Add(nil)
	ref.Add(later)

	require.Equal(ref.Err, got.err)
	require.Same(ref.Err, got.err)
	require.Same(seed, got.err, "seeded error must win over later non-nil errors")
}
