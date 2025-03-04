/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

// Package events implements a log of coordinator events.
package events

import (
	"encoding/json"
	"net/http"
	"time"
)

// ActivationEvent is an event that is logged when a marble is activated.
type ActivationEvent struct {
	MarbleType string `json:"marbleType"`
	UUID       string `json:"uuid"`
	Quote      []byte `json:"quote"`
}

// Event represents a single event in the event log.
type Event struct {
	Timestamp  time.Time        `json:"time"`
	Activation *ActivationEvent `json:"activation"`
}

// Log is a log of coordinator events.
type Log struct {
	events []Event
}

// NewLog creates a new log.
func NewLog() *Log {
	return &Log{}
}

// Activation adds an activation event to the log.
func (l *Log) Activation(marbleType string, uuid string, quote []byte) {
	l.events = append(l.events, Event{
		Timestamp:  time.Now(),
		Activation: &ActivationEvent{MarbleType: marbleType, UUID: uuid, Quote: quote},
	})
}

// Handler returns a http.HandlerFunc which writes the log as JSON array.
func (l *Log) Handler() http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(l.events)
	})
}
