package structs

//AuditEntry represents an Audit entry in the database
type AuditEntry struct {
	ID          int    `json:"id"`
	Issuer      string `json:"issuer"`
	Username    string `json:"user"`
	Message     int64  `json:"message"`
	Success     bool   `json:"result"`
	ValidatedOn string `json:"date"`
}
