package services

import "github.com/SwanHtetAungPhyo/didStorage/internal/models"

type NodeServices interface {
	AddTx(tx *models.Transaction) error
	GetTx(hash string) (*models.Transaction, error)
	GetLatestTx() (string, error)
}
