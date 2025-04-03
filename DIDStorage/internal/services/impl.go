package services

import (
	"github.com/SwanHtetAungPhyo/didStorage/internal/models"
	"github.com/sirupsen/logrus"
)

type NodeServiceImpl struct {
	log *logrus.Logger
	dag *models.DAG
}

func NewNodeServiceImpl(log *logrus.Logger, dag *models.DAG) *NodeServiceImpl {
	return &NodeServiceImpl{log: log,
		dag: dag}
}

func (n *NodeServiceImpl) AddTx(tx *models.Transaction) (string, error) {
	txId, err := n.dag.AddDID(tx)
	if err != nil {
		return " ", err
	}
	return txId, nil
}

func (n *NodeServiceImpl) GetTx(hash string) (*models.Transaction, error) {
	//TODO implement me
	panic("implement me")
}

func (n *NodeServiceImpl) GetLatestTx() (string, error) {
	n.log.Debug("GetLatestTx")
	latestHash, err := n.dag.GetLatestTxHash()
	if err != nil {
		n.log.WithFields(logrus.Fields{
			"error": err,
		}).Infoln("GetLatestTx Failed")
		n.log.WithError(err).Error("GetLatestTx")
		return "", err
	}
	n.log.Debug("GetLatestTx Success")
	return latestHash, nil
}
