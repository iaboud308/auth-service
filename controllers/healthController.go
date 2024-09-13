package controllers

import (
	"net/http"
)

// HealthCheck simply returns a message indicating the service is up
func HealthCheck(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Service is up and running"))
}
