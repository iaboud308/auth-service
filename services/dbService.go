package services

import (
	"auth-service/config"
	"auth-service/models"
	"database/sql"
	"fmt"
	"sync"
	"time"

	_ "github.com/lib/pq"
)

var dbPool = make(map[string]*sql.DB)
var dbPoolMutex sync.Mutex

func GetDBConnection(systemId int, tenantId int) (*sql.DB, error) {
	dbKey := fmt.Sprintf("%d_%d", systemId, tenantId)
	dbPoolMutex.Lock()
	defer dbPoolMutex.Unlock()

	if db, exists := dbPool[dbKey]; exists {
		return db, nil // Return the existing connection if available
	}

	// Build the connection string (your config function)
	connStr, err := config.GetDBConnectionString(systemId, tenantId)
	if err != nil {
		return nil, err
	}

	// Create the DB connection pool with appropriate settings
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, fmt.Errorf("unable to connect to the database for systemId %d and tenantId %d: %w", systemId, tenantId, err)
	}

	// Set connection pooling parameters
	db.SetMaxOpenConns(10) // Maximum open connections
	db.SetMaxIdleConns(5)  // Maximum idle connections
	db.SetConnMaxLifetime(30 * time.Minute)

	// Ping the database to ensure connection is established
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("unable to reach the database for systemId %d and tenantId %d: %w", systemId, tenantId, err)
	}

	// Store the connection pool in the map
	dbPool[dbKey] = db
	return db, nil
}

func scanRow(row *sql.Row, data []interface{}) error {
	return row.Scan(data...)
}

// Dynamic Column Scanning for multiple rows
// func scanRows(rows *sql.Rows, data []interface{}) error {
// 	return rows.Scan(data...)
// }

// GetMultipleRows for any table with dynamic columns
func GetMultipleRows(executor interface{}, query string, args []interface{}, data *[]interface{}, scanFields []interface{}, logInfo models.LogInfo) (int, error) {
	var rows *sql.Rows
	var err error

	switch ex := executor.(type) {
	case *sql.DB:
		rows, err = ex.Query(query, args...)
	case *sql.Tx:
		rows, err = ex.Query(query, args...)
	default:
		return 0, fmt.Errorf("unsupported executor type: %T", executor)
	}

	if err != nil {
		LogEntry(logInfo.Action, "error", fmt.Sprintf("Error executing query: %s", err.Error()), logInfo.User, logInfo.AdditionalData)
		return 0, err
	}
	defer rows.Close()

	var rowCount int

	for rows.Next() {
		if err := rows.Scan(scanFields...); err != nil {
			LogEntry(logInfo.Action, "error", fmt.Sprintf("Error scanning rows: %s", err.Error()), logInfo.User, logInfo.AdditionalData)
			return 0, err
		}

		*data = append(*data, scanFields)
		rowCount++
	}

	if err := rows.Err(); err != nil {
		LogEntry(logInfo.Action, "error", fmt.Sprintf("Error iterating over rows: %s", err.Error()), logInfo.User, logInfo.AdditionalData)
		return rowCount, err
	}

	if rowCount == 0 {
		LogEntry(logInfo.Action, "info", "No rows found", logInfo.User, logInfo.AdditionalData)
		return rowCount, nil
	}

	LogEntry(logInfo.Action, "info", logInfo.Message+" successfully", logInfo.User, logInfo.AdditionalData)
	return rowCount, nil
}

// Example Get function for retrieving a single row without reflection
func GetSingleRow(executor interface{}, query string, args []interface{}, data []interface{}, logInfo models.LogInfo) (int64, error) {
	var row *sql.Row
	switch ex := executor.(type) {
	case *sql.DB:
		row = ex.QueryRow(query, args...)
	case *sql.Tx:
		row = ex.QueryRow(query, args...)
	default:
		return 0, fmt.Errorf("unsupported executor type: %T", executor)
	}

	err := scanRow(row, data)
	if err != nil {
		if err == sql.ErrNoRows {
			LogEntry(logInfo.Action, "info", "No rows found", logInfo.User, logInfo.AdditionalData)
			return 0, nil
		}
		LogEntry(logInfo.Action, "error", fmt.Sprintf("Error executing query: %s", err.Error()), logInfo.User, logInfo.AdditionalData)
		return 0, err
	}

	LogEntry(logInfo.Action, "info", "Query executed successfully", logInfo.User, logInfo.AdditionalData)
	return 1, nil
}

// Example Insert function
func InsertRow(executor interface{}, query string, args []interface{}, logInfo models.LogInfo) (int64, error) {
	var result sql.Result
	var err error

	switch exec := executor.(type) {
	case *sql.DB:
		result, err = exec.Exec(query, args...)
	case *sql.Tx:
		result, err = exec.Exec(query, args...)
	default:
		return 0, fmt.Errorf("unsupported executor type")
	}

	if err != nil {
		LogEntry(logInfo.Action, "error", fmt.Sprintf("Error executing insert: %s", err.Error()), logInfo.User, logInfo.AdditionalData)
		return 0, err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil || rowsAffected == 0 {
		LogEntry(logInfo.Action, "error", "Insert failed or no rows affected", logInfo.User, logInfo.AdditionalData)
		return 0, fmt.Errorf("no rows affected")
	}

	LogEntry(logInfo.Action, "info", "Insert executed successfully", logInfo.User, logInfo.AdditionalData)
	return rowsAffected, nil
}

// Example Update function
func UpdateRow(executor interface{}, query string, args []interface{}, logInfo models.LogInfo) (int64, error) {
	var result sql.Result
	var err error

	switch exec := executor.(type) {
	case *sql.DB:
		result, err = exec.Exec(query, args...)
	case *sql.Tx:
		result, err = exec.Exec(query, args...)
	default:
		return 0, fmt.Errorf("unsupported executor type")
	}

	if err != nil {
		LogEntry(logInfo.Action, "error", fmt.Sprintf("Error executing update: %s", err.Error()), logInfo.User, logInfo.AdditionalData)
		return 0, err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil || rowsAffected == 0 {
		LogEntry(logInfo.Action, "error", "Update failed or no rows affected", logInfo.User, logInfo.AdditionalData)
		return 0, fmt.Errorf("no rows affected")
	}

	LogEntry(logInfo.Action, "info", fmt.Sprintf("%d rows affected", rowsAffected), logInfo.User, logInfo.AdditionalData)
	return rowsAffected, nil
}

// DeleteRow function that deletes a row from the specified table
func DeleteRow(executor interface{}, query string, args []interface{}, logInfo models.LogInfo) (int64, error) {

	var result sql.Result
	var err error

	switch exec := executor.(type) {
	case *sql.DB:
		result, err = exec.Exec(query, args...)
	case *sql.Tx:
		result, err = exec.Exec(query, args...)
	default:
		return 0, fmt.Errorf("unsupported executor type")
	}

	if err != nil {
		LogEntry(logInfo.Action, "error", fmt.Sprintf("Error executing delete: %s", err.Error()), logInfo.User, logInfo.AdditionalData)
		return 0, err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		LogEntry(logInfo.Action, "error", fmt.Sprintf("Error getting rows affected: %s", err.Error()), logInfo.User, logInfo.AdditionalData)
		return 0, err
	}

	if rowsAffected == 0 {
		LogEntry(logInfo.Action, "info", "No rows were deleted", logInfo.User, logInfo.AdditionalData)
		return 0, nil
	}

	LogEntry(logInfo.Action, "info", fmt.Sprintf("%d rows deleted successfully", rowsAffected), logInfo.User, logInfo.AdditionalData)
	return rowsAffected, nil
}
