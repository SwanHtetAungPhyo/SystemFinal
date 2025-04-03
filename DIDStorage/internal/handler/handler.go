package handler

import "github.com/gofiber/fiber/v2"

type HandlerMethod interface {
	SubmitTxHandler(c *fiber.Ctx) error
	GetTrixHandler(c *fiber.Ctx) error
	GetLatestTransactionHandler(c *fiber.Ctx) error
}
