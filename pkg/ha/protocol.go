// Package ha implements high availability peer-to-peer state synchronization
// between BNG HA pairs (active/standby).
//
// When two BNGs are paired for HA at a site:
// - Active serves subscriber traffic
// - Standby shadows active's session state
// - On failover, standby has all state needed to take over
package ha

import (
	"encoding/json"
	"time"
)

// Role represents the HA role of a BNG node.
type Role string

const (
	// RoleActive indicates this node is the active BNG serving traffic.
	RoleActive Role = "active"
	// RoleStandby indicates this node is the standby BNG shadowing state.
	RoleStandby Role = "standby"
	// RoleUnknown indicates the role has not been determined yet.
	RoleUnknown Role = "unknown"
)

// PartnerInfo contains information about the HA partner node.
type PartnerInfo struct {
	// NodeID is the partner's unique identifier.
	NodeID string `json:"node_id"`
	// Endpoint is the partner's sync endpoint (e.g., "10.0.0.1:9000").
	Endpoint string `json:"endpoint"`
}

// SyncMessageType represents the type of sync message.
type SyncMessageType string

const (
	// SyncTypeFull indicates a full state sync (all sessions).
	SyncTypeFull SyncMessageType = "full"
	// SyncTypeAdd indicates a new session was added.
	SyncTypeAdd SyncMessageType = "add"
	// SyncTypeUpdate indicates a session was updated.
	SyncTypeUpdate SyncMessageType = "update"
	// SyncTypeDelete indicates a session was deleted.
	SyncTypeDelete SyncMessageType = "delete"
	// SyncTypeHeartbeat indicates a keepalive message.
	SyncTypeHeartbeat SyncMessageType = "heartbeat"
	// SyncTypeFullRequest indicates a request for full sync.
	SyncTypeFullRequest SyncMessageType = "full_request"
)

// SyncMessage represents a state synchronization message between HA pairs.
type SyncMessage struct {
	// Type indicates what kind of sync operation this is.
	Type SyncMessageType `json:"type"`

	// Sessions contains the session state being synced.
	// For full sync, this contains all sessions.
	// For add/update, this contains the affected session(s).
	// For delete, this contains session IDs only.
	Sessions []SessionState `json:"sessions,omitempty"`

	// Timestamp is when this message was generated.
	Timestamp time.Time `json:"timestamp"`

	// SequenceNum is used for ordering incremental updates.
	SequenceNum uint64 `json:"sequence_num,omitempty"`

	// NodeID identifies the sender.
	NodeID string `json:"node_id"`
}

// SessionState represents the synchronizable state of a subscriber session.
// This is the minimal state needed for the standby to take over.
type SessionState struct {
	// Identification
	SessionID    string `json:"session_id"`
	SubscriberID string `json:"subscriber_id"`
	MAC          string `json:"mac"`

	// Network assignment
	IP      string `json:"ip"`
	IPv6    string `json:"ipv6,omitempty"`
	Gateway string `json:"gateway,omitempty"`
	VLAN    int    `json:"vlan"`
	STag    uint16 `json:"s_tag,omitempty"`
	CTag    uint16 `json:"c_tag,omitempty"`

	// Service configuration
	QoSProfile      string `json:"qos_profile,omitempty"`
	DownloadRateBps uint64 `json:"download_rate_bps,omitempty"`
	UploadRateBps   uint64 `json:"upload_rate_bps,omitempty"`

	// Session metadata
	SessionType string `json:"session_type"` // "ipoe" or "pppoe"
	ISPID       string `json:"isp_id,omitempty"`
	Username    string `json:"username,omitempty"`

	// Timing
	CreatedAt    time.Time `json:"created_at"`
	LastActivity time.Time `json:"last_activity"`

	// State
	State        string `json:"state"`
	WalledGarden bool   `json:"walled_garden"`

	// Statistics (optional, for monitoring)
	BytesIn  uint64 `json:"bytes_in,omitempty"`
	BytesOut uint64 `json:"bytes_out,omitempty"`
}

// SyncStats contains statistics about the sync process.
type SyncStats struct {
	// LastSyncTime is when we last successfully synced.
	LastSyncTime time.Time `json:"last_sync_time"`

	// SessionsSynced is the total number of sessions currently synced.
	SessionsSynced int `json:"sessions_synced"`

	// MessagesReceived is the total number of sync messages received.
	MessagesReceived uint64 `json:"messages_received"`

	// MessagesSent is the total number of sync messages sent.
	MessagesSent uint64 `json:"messages_sent"`

	// BytesReceived is the total bytes received.
	BytesReceived uint64 `json:"bytes_received"`

	// BytesSent is the total bytes sent.
	BytesSent uint64 `json:"bytes_sent"`

	// LastError is the last error encountered (if any).
	LastError string `json:"last_error,omitempty"`

	// LastErrorTime is when the last error occurred.
	LastErrorTime time.Time `json:"last_error_time,omitempty"`

	// Connected indicates whether we're connected to our partner.
	Connected bool `json:"connected"`

	// PartnerNodeID is the node ID of our partner (if connected).
	PartnerNodeID string `json:"partner_node_id,omitempty"`
}

// Encode serializes a SyncMessage to JSON bytes.
func (m *SyncMessage) Encode() ([]byte, error) {
	return json.Marshal(m)
}

// DecodeSyncMessage deserializes a SyncMessage from JSON bytes.
func DecodeSyncMessage(data []byte) (*SyncMessage, error) {
	var m SyncMessage
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// SessionStore is the interface for accessing session state.
// This abstracts the underlying session storage mechanism.
type SessionStore interface {
	// GetSession returns a session by ID.
	GetSession(sessionID string) (*SessionState, bool)

	// GetAllSessions returns all active sessions.
	GetAllSessions() []SessionState

	// PutSession adds or updates a session.
	PutSession(session *SessionState) error

	// DeleteSession removes a session.
	DeleteSession(sessionID string) error

	// GetSessionCount returns the number of active sessions.
	GetSessionCount() int
}

// ChangeNotifier is called when session state changes.
type ChangeNotifier func(changeType SyncMessageType, session *SessionState)
