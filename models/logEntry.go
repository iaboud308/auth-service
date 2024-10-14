package models

type LogEntry struct {
	Action         string                 `json:"action"`
	System         string                 `json:"system"`
	Tenant         string                 `json:"hospital"`
	Service        string                 `json:"service"`
	Level          string                 `json:"level"`
	Message        string                 `json:"message"`
	UserId         int                    `json:"user_id"`
	AdditionalData map[string]interface{} `json:"additional_data"`
}

type LogInfo struct {
	Action         string                 `json:"action"`
	Message        string                 `json:"message"`
	User           User                   `json:"user"`
	AdditionalData map[string]interface{} `json:"additional_data"`
}
