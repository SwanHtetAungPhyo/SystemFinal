package handler

import (
	"github.com/SwanHtetAungPhyo/didStorage/internal/models"
	"github.com/SwanHtetAungPhyo/didStorage/internal/services"
	"github.com/SwanHtetAungPhyo/didStorage/pkg/utils"
	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
)

type Impl struct {
	log          *logrus.Logger
	servicesImpl *services.NodeServiceImpl
}

func NewHandlerImpl(log *logrus.Logger, servicesImpl *services.NodeServiceImpl) *Impl {
	return &Impl{
		log:          log,
		servicesImpl: servicesImpl,
	}
}

func (h *Impl) SubmitTxHandler(c *fiber.Ctx) error {
	var newTx *models.Transaction
	if err := c.BodyParser(&newTx); err != nil {
		c.Status(fiber.StatusBadRequest)
		return c.JSON(utils.Response{
			Status:  fiber.StatusBadRequest,
			Message: err.Error(),
			Data:    nil,
		})
	}
	if didData, ok := newTx.Data.(map[string]interface{}); ok {
		newTx.Data = &models.DID{
			DID:   didData["DID"].(string),
			Owner: didData["owner"].(string),
		}
	}

	txId, err := h.servicesImpl.AddTx(newTx)
	if err != nil {
		c.Status(fiber.StatusBadRequest)
		return c.JSON(utils.Response{
			Status:  fiber.StatusBadRequest,
			Message: err.Error(),
		})
	}
	return c.JSON(utils.Response{
		Status:  fiber.StatusOK,
		Message: "success",
		Data:    txId,
	})
}

func (h *Impl) GetTrixHandler(c *fiber.Ctx) error {
	//TODO implement me
	panic("implement me")
}

func (h *Impl) GetLatestTransactionHandler(c *fiber.Ctx) error {
	h.log.Debug("get latest transaction")

	latestHash, err := h.servicesImpl.GetLatestTx()
	if err != nil {
		c.Status(fiber.StatusBadRequest)
		return c.JSON(utils.Response{
			Status:  fiber.StatusBadRequest,
			Message: err.Error(),
			Data:    nil,
		})
	}
	return c.JSON(utils.Response{
		Status:  fiber.StatusOK,
		Message: "success",
		Data:    latestHash,
	})
}
