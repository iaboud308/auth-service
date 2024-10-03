package services

import (
	"auth-service/config"
	"auth-service/models"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

func LogEntry(action string, system string, hospital string, level string, message string, userId int, additionalData map[string]interface{}) {
	var logEntry models.LogEntry
	logEntry.Action = action
	logEntry.System = system
	logEntry.Hospital = hospital
	logEntry.Service = "auth-service"
	logEntry.Level = level
	logEntry.Message = message
	logEntry.UserId = userId
	logEntry.AdditionalData = additionalData

	// Serialize log entry to JSON
	logJSON, err := json.Marshal(logEntry)
	if err != nil {
		fmt.Println("Error serializing log entry:", err)
		return
	}

	SaveLogEntry(logJSON)
}

func SaveLogEntry(logJSON []byte) {

	// Prepare the request
	req, err := http.NewRequest("POST", config.LoggingServiceUrl, bytes.NewBuffer(logJSON))
	if err != nil {
		fmt.Println("Error creating request to logging service:", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")

	// Send the request to the logging service
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending log to logging service:", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("Failed to send log. Status code: %d\n", resp.StatusCode)
	}

}
