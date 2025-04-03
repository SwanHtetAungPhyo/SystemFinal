package cmd

import (
	"context"
	"github.com/SwanHtetAungPhyo/didStorage/internal/handler"
	"github.com/SwanHtetAungPhyo/didStorage/internal/models"
	"github.com/SwanHtetAungPhyo/didStorage/internal/services"
	"github.com/SwanHtetAungPhyo/didStorage/pkg/utils"
	"github.com/gofiber/fiber/v2"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func Start(port string, dag *models.DAG) {
	startLog := utils.GetLogger()
	app := fiber.New(fiber.Config{
		DisableStartupMessage: false,
	})

	servicesImpl := services.NewNodeServiceImpl(startLog, dag)
	handlers := handler.NewHandlerImpl(startLog, servicesImpl)

	app.Get("/latest", handlers.GetLatestTransactionHandler)
	app.Post("/submit", handlers.SubmitTxHandler)

	go func() {
		if err := app.Listen(port); err != nil {
			startLog.Fatalf(err.Error())
			return
		}
	}()

	osChannel := make(chan os.Signal, 1)
	signal.Notify(osChannel, os.Interrupt)
	signal.Notify(osChannel, syscall.SIGTERM)
	signal.Notify(osChannel, os.Kill)

	<-osChannel
	startLog.Println("Shutting down...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := app.ShutdownWithContext(ctx); err != nil {
		startLog.Errorln(err.Error())
		return
	}
}
