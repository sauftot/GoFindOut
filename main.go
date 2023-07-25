package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/term"
)

var (
	path = ""
	wg   sync.WaitGroup
)

// encrypt and file or folder in the path
func main() {
	executablePath, err := os.Executable()
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	path = filepath.Dir(executablePath)
	welcome()

	for {
		fmt.Print("GoFindOut> ")
		var command string
		fmt.Scanln(&command)
		comArr := strings.Split(command, " ")
		switch strings.ToLower(comArr[0]) {
		case "h":
			help()
		case "e":
			k := len(comArr)
			if k < 2 {
				fmt.Println("Not enough arguments. Use help for a list of commands")
				continue
			}
			fmt.Println("Enter your password: ")
			p, err := term.ReadPassword(int(os.Stdin.Fd()))
			if err != nil {
				fmt.Println("ENCRYPT: ReadPassword:", err)
				return
			}
			for i := 0; i < k; i++ {
				wg.Add(1)
				go encrypt(comArr[i+1], p)
				i++
			}

			encrypt()
		case "d":
			decrypt()
		case "cd":
			changeDirectory()
		case "ls":
			list()
		case "pwd":
			fmt.Println(path)
		case "q":
			return
		default:
			fmt.Println("Unknown. Use help for a list of commands")
		}
	}
}

func welcome() {
	fmt.Println("Welcome to GoFindOut, a simple tool to encrypt/decrypt your files and folders.")
	help()
}

func help() {
	fmt.Println("The following commands are available: ")
	fmt.Println("\t h | shows this help message")
	fmt.Println("\t e [files or folders] | encrypts the file or folder in the path with the password")
	fmt.Println("\t d [files or folders] | decrypts the file or folder in the path with the password")
	fmt.Println("\t Multiple files or folders in the same directory can be encrypted or decrypted by separating them with a space.")
	fmt.Println("\t cd [path] | shows this help message")
	fmt.Println("\t ls | lists the files and folders in the path")
	fmt.Println("\t pwd | prints the current path")
	fmt.Println("\t q | quits the program")
}

func encrypt(file string, p []byte) {
	defer wg.Done()
}

func decrypt() {
}

func changeDirectory() {
}

func list() {
}

func deriveKey(password string) []byte {
	return pbkdf2.Key([]byte(password), []byte("useless"), 4096, 32, sha256.New)
}
