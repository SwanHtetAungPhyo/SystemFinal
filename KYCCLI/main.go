package main

import (
	"fmt"

	"github.com/AlecAivazis/survey/v2"
	"github.com/SwanHtetAungPhyo/KYCLI/internal/ui"
)

func UIOption() {
	for {
		options := []string{
			"Create",
			"Get",
			"Register",
			"GetDID",
			"Authenticate",
		}

		var selectedOption string
		err := survey.AskOne(&survey.Select{
			Message: "Choose an option:",
			Options: options,
		}, &selectedOption)

		if err != nil {
			fmt.Println("Error:", err)
			return
		}

		switch selectedOption {
		case "Create":
			fmt.Println("You selected to view user information.")
			ui.CreateAccount()
		case "Get":
			fmt.Println("You selected to edit user information.")
		case "Register":
			fmt.Println("Exiting the application.")
			ui.Register()
		case "GetDID":
			ui.DID()
		case "Authenticate":
			fmt.Print("Authenticate")

		default:
			fmt.Println("Invalid selection. Please try again.")
		}
	}
}

func main() {
	UIOption()
}
