package models

type LogEntry struct {
	Action         string                 `json:"action"`
	System         string                 `json:"system"`
	Hospital       string                 `json:"hospital"`
	Service        string                 `json:"service"`
	Level          string                 `json:"level"`
	Message        string                 `json:"message"`
	UserId         int                    `json:"user_id"`
	AdditionalData map[string]interface{} `json:"additional_data"`
}
