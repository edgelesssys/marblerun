/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package clientapi

import (
	"fmt"

	"github.com/edgelesssys/marblerun/coordinator/store/wrapper"
)

type mnfEntry[T any] interface {
	Equal(T) bool
}

type iteratorGetter interface {
	GetIterator(string) (wrapper.Iterator, error)
}

// updateManifestEntries updates the given manifest entries.
func updateManifestEntries[T mnfEntry[T]](
	store iteratorGetter, entry string, newEntries map[string]T,
	get func(string) (T, error), put func(string, T) error, del func(string) error,
) error {
	// Get existing entries
	existingEntries, err := getExistingEntries(store, entry, get)
	if err != nil {
		return fmt.Errorf("getting existing %s: %w", entry, err)
	}

	// Check existing entries against new entries
	added, removed, equal := compareKeys(existingEntries, newEntries)

	// Delete now unused entries
	for _, name := range removed {
		if err := del(name); err != nil {
			return fmt.Errorf("deleting %s: %w", entry, err)
		}
	}

	// Delete entries that have changed
	for _, name := range equal {
		if !existingEntries[name].Equal(newEntries[name]) {
			// if entry has changed, delete the old one
			if err := del(name); err != nil {
				return fmt.Errorf("deleting %s: %w", entry, err)
			}
			// add entry to list of entries to add
			added = append(added, name)
		}
	}

	// Add new entries
	for _, name := range added {
		if err := put(name, newEntries[name]); err != nil {
			return fmt.Errorf("saving %s to store: %w", entry, err)
		}
	}

	return nil
}

// getExistingEntries retrieves a map of entries from the store.
func getExistingEntries[T any](store iteratorGetter, entry string, get func(string) (T, error)) (map[string]T, error) {
	iter, err := store.GetIterator(entry)
	if err != nil {
		return nil, fmt.Errorf("getting %s iterator: %w", entry, err)
	}
	existingEntries := make(map[string]T)
	for iter.HasNext() {
		name, err := iter.GetNext()
		if err != nil {
			return nil, fmt.Errorf("getting next %s: %w", entry, err)
		}
		e, err := get(name)
		if err != nil {
			return nil, fmt.Errorf("getting %s: %w", entry, err)
		}
		existingEntries[name] = e
	}
	return existingEntries, nil
}

// compareKeys compares the keys of two maps and returns the added, removed and equal keys.
func compareKeys[T, U any](oldMap map[string]T, newMap map[string]U) (added, removed, equal []string) {
	for k := range oldMap {
		if _, ok := newMap[k]; !ok {
			removed = append(removed, k)
		} else {
			equal = append(equal, k)
		}
	}
	for k := range newMap {
		if _, ok := oldMap[k]; !ok {
			added = append(added, k)
		}
	}
	return added, removed, equal
}
