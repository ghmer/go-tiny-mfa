package structs

import "time"

//AuditEntry represents an Audit entry in the database
type AuditEntry struct {
	ID          int    `json:"id"`
	Issuer      string `json:"issuer"`
	Username    string `json:"user"`
	Message     int64  `json:"message"`
	Success     bool   `json:"result"`
	ValidatedOn string `json:"date"`
}

//AuditQueryParameter contains parameters for querying audit entries
type AuditQueryParameter struct {
	BaseQuery        string
	Before           time.Time
	After            time.Time
	SourceDateFormat string
	TargetDateFormat string
}

func NewAuditQueryParameter() AuditQueryParameter {
	return AuditQueryParameter{SourceDateFormat: "2006-01-02:15:04:05", TargetDateFormat: "2006-01-02 15:04:05"}
}
