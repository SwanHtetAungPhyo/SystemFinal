package main

import (
	"github.com/SwanHtetAungPhyo/didStorage/cmd"
	"github.com/SwanHtetAungPhyo/didStorage/internal/models"
	"github.com/SwanHtetAungPhyo/didStorage/pkg/utils"
)

func main() {
	utils.InitLogger()
	logger := utils.GetLogger()
	logger.Infoln("Starting DID Server")

	dag := models.NewDAG()

	cmd.Start(":9000", dag)
}
