package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"syscall"

	"github.com/enolgor/flagsenv"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh/terminal"
	"gopkg.in/yaml.v2"
)

const (
	WHITELIST = iota
	BLACKLIST
)

type AuthDef struct {
	Users  *Users  `yaml:"users"`
	Groups *Groups `yaml:"groups"`
}

type HashPassword string

type Users map[string]*HashPassword

type Groups map[string]*[]string

func NewPassword(plain string) (*HashPassword, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	hp := HashPassword(hash)
	return &hp, nil
}

func (hp *HashPassword) Compare(plain string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(*hp), []byte(plain))
	return err == nil
}

func (ad *AuthDef) AuthUser(username string, plain string) error {
	hashPwd, ok := (*ad.Users)[username]
	if !ok {
		return fmt.Errorf("User %s not found", username)
	}
	if !hashPwd.Compare(plain) {
		return fmt.Errorf("Wrong password for user %s", username)
	}
	return nil
}

func (ad *AuthDef) GetUserList(groupNames ...string) []string {
	userList := []string{}
	for _, groupName := range groupNames {
		if group, ok := (*ad.Groups)[groupName]; ok {
			for _, userOfGroup := range *group {
				userList = append(userList, userOfGroup)
			}
		}
	}
	return userList
}

var file string

const (
	fileFlagName = "f"
	fileDefault  = "./auth.yml"
	fileUsage    = "Specify yml auth file"
	fileEnv      = "AUTH_FILE"
)

var userToAdd string

const (
	userToAddFlagName = "a"
	userToAddDefault  = ""
	userToAddUsage    = "User to add"
)

func init() {
	fe := flagsenv.NewFlagsEnv(nil)
	fe.Env(fileEnv).StringVar(&file, fileFlagName, fileDefault, fileUsage)
	flag.StringVar(&userToAdd, userToAddFlagName, userToAddDefault, userToAddUsage)
	flag.Parse()
}

func main() {
	authDef := &AuthDef{Users: &Users{}, Groups: &Groups{}}
	f, err := os.Open(file)

	if err == nil {
		dec := yaml.NewDecoder(f)
		err = dec.Decode(authDef)
		if err != nil {
			panic(err)
		}
	}

	if userToAdd != userToAddDefault {
		addUserToFile(authDef, f)
		os.Exit(0)
	}
	http.HandleFunc("/whitelist", handleAuth(authDef, WHITELIST))
	http.HandleFunc("/blacklist", handleAuth(authDef, BLACKLIST))
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleAuth(authDef *AuthDef, mode int) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		values := req.URL.Query()
		csvGroups, _ := values["g"]
		csvUsers, _ := values["u"]
		userList := []string{}
		groupList := []string{}
		for _, csvGroup := range csvGroups {
			for _, group := range strings.Split(csvGroup, ",") {
				groupList = append(groupList, strings.TrimSpace(group))
			}
		}
		for _, csvUser := range csvUsers {
			for _, user := range strings.Split(csvUser, ",") {
				userList = append(userList, strings.TrimSpace(user))
			}
		}
		userList = append(userList, authDef.GetUserList(groupList...)...)
		user, pass, ok := req.BasicAuth()
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		userInList := false
		for _, userOfList := range userList {
			if userOfList == user {
				userInList = true
				break
			}
		}
		if mode == WHITELIST && !userInList ||
			mode == BLACKLIST && userInList ||
			authDef.AuthUser(user, pass) != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		return
	}
}

func addUserToFile(authDef *AuthDef, f *os.File) {
	plainPassword, err := readPassword()
	if err != nil {
		fmt.Printf("Error: %s", err)
		return
	}
	hashPassword, err := NewPassword(plainPassword)
	if err != nil {
		return
	}
	(*authDef.Users)[userToAdd] = hashPassword
	encoder := yaml.NewEncoder(os.Stdout)
	encoder.Encode(authDef)
	return
}

func readPassword() (string, error) {

	var bytePassword, byteRetypePassword []byte
	var password, retypedPassword string
	var err error

	for {
		fmt.Print("Enter Password: ")
		bytePassword, err = terminal.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return "", err
		}
		fmt.Println()
		password = strings.TrimSpace(string(bytePassword))
		if password != "" {
			break
		}
	}

	for {
		fmt.Print("Re-Type Password: ")
		byteRetypePassword, err = terminal.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return "", err
		}
		fmt.Println()
		retypedPassword = strings.TrimSpace(string(byteRetypePassword))
		if retypedPassword != "" {
			break
		}
	}

	if password != retypedPassword {
		return "", fmt.Errorf("Passwords do not match")
	}
	return password, nil
}
