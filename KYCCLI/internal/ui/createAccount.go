package ui

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/AlecAivazis/survey/v2"
	"github.com/go-resty/resty/v2"
)

type User struct {
	FullName  string `json:"full_name"`
	Email     string `json:"email"`
	Password  string `json:"password"`
	Biometric string `json:"biometric"`
	National  string `json:"national"`
}

func CreateAccount() {
	user, err := CollectUserInput()
	if err != nil {
		log.Fatal("Error collecting user input:", err)
		return
	}
	client := resty.New().
		SetTimeout(5 * time.Second).
		SetRetryCount(3).
		SetRetryWaitTime(1 * time.Second)
	resp, err := client.R().
		SetHeader("Content-Type", "application/json").
		SetBody(user).
		Post("http://localhost:8080/createAccount")

	if err != nil {
		log.Fatalf("Request failed: %v", err)
	}
	fmt.Println("Response Status:", resp.Status())
	fmt.Println("Response Time:", resp.Time())
	fmt.Println("Response Body:", string(resp.Body()))
	saveToFile(user)
}

func Register() {
	if _, err := os.Stat("./user.json"); os.IsNotExist(err) {
		fmt.Println("No user account found. Please create an account first.")
		return
	}

	file, err := os.Open("./user.json")
	if err != nil {
		log.Fatal("Error opening file: ", err)
		return
	}
	defer file.Close()

	var user User
	err = json.NewDecoder(file).Decode(&user)
	if err != nil {
		log.Fatal("Error reading user data: ", err)
		return
	}
	client := resty.New().
		SetTimeout(5 * time.Second).
		SetRetryCount(3).
		SetRetryWaitTime(1 * time.Second)
	resp, err := client.R().
		SetHeader("Content-Type", "application/json").
		SetBody(user).
		Post("http://localhost:8080/getAccount")

	if err != nil {
		log.Fatalf("Request failed: %v", err)
	}
	fmt.Println("Response Status:", resp.Status())
	fmt.Println("Response Time:", resp.Time())
	fmt.Println("Response Body:", string(resp.Body()))
}

func DID() {
	if _, err := os.Stat("./user.json"); os.IsNotExist(err) {
		fmt.Println("No user account found. Please create an account first.")
		return
	}

	file, err := os.Open("./user.json")
	if err != nil {
		log.Fatal("Error opening file: ", err)
		return
	}
	defer file.Close()

	var user User
	err = json.NewDecoder(file).Decode(&user)
	if err != nil {
		log.Fatal("Error reading user data: ", err)
		return
	}

	client := resty.New().
		SetTimeout(5 * time.Second).
		SetRetryCount(3).
		SetRetryWaitTime(1 * time.Second)

	resp, err := client.R().
		SetHeader("Content-Type", "application/json").
		SetBody(user).
		Post("http://localhost:8080/did")

	if err != nil {
		log.Fatalf("Request failed: %v", err)
	}

	fmt.Println("Response Status:", resp.Status())
	fmt.Println("Response Time:", resp.Time())

	fmt.Println(string(resp.Body()))
}

func saveToFile(user User) {
	file, err := os.Create("./user.json")
	if err != nil {
		log.Fatal("Error creating file:", err)
		return
	}
	defer file.Close()

	jsonData, err := json.MarshalIndent(user, " ", "	")
	if err != nil {
		log.Fatal("Error marshaling user data:", err)
		return
	}
	_, err = file.Write(jsonData)
	if err != nil {
		log.Fatal("Error writing user data to file:", err)
	}
}

func DisplayUserInfo() {
	file, err := os.Open("./user.json")
	if err != nil {
		log.Fatal("Error opening file: ", err)
		return
	}
	defer file.Close()

	var user User
	err = json.NewDecoder(file).Decode(&user)
	if err != nil {
		log.Fatal("Error reading user data: ", err)
		return
	}

	fmt.Println("User Information:")
	fmt.Printf("Full Name: %s\n", user.FullName)
	fmt.Printf("Email: %s\n", user.Email)
	fmt.Printf("Biometric: %s\n", user.Biometric)
	fmt.Printf("NationalId : %s\n", user.National)
}

func getSurveyQuestions() []*survey.Question {
	return []*survey.Question{
		{
			Name: "FullName",
			Prompt: &survey.Input{
				Message: "What is your full name?",
				Default: "John Doe",
			},
			Validate: survey.Required,
		},
		{
			Name: "Email",
			Prompt: &survey.Input{
				Message: "What is your email?",
				Default: "example@mail.com",
			},
			Validate: survey.Required,
		},
		{
			Name: "Password",
			Prompt: &survey.Password{
				Message: "What is your password?",
				Help:    "Password should be at least 8 characters.",
			},
			Validate: survey.Required,
		},
		{
			Name: "Biometric",
			Prompt: &survey.Input{
				Message: "Please provide your biometric information (e.g., fingerprint, face scan)",
			},
			Validate: survey.Required,
		},
		{
			Name: "National",
			Prompt: &survey.Input{
				Message: "Please input the national ID",
			},
			Validate: survey.Required,
		},
	}
}

func CollectUserInput() (User, error) {
	var user User
	questions := getSurveyQuestions()

	// Ask the questions and capture the answers
	err := survey.Ask(questions, &user)
	if err != nil {
		return user, err
	}

	// Log the captured user data
	fmt.Printf("Captured Data: %+v\n", user)

	return user, nil
}
