package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io/ioutil"
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
			if k == 2 && comArr[1] == "*" {
				files, err := ioutil.ReadDir(path)
				if err != nil {
					fmt.Println("ENCRYPT: ReadDir:", err)
					return
				}

				for _, file := range files {
					// Check if it's a regular file (not a directory)
					if file.Mode().IsRegular() {
						wg.Add(1)
						go encrypt(file.Name(), p)
					}
				}
			} else {
				for i := 0; i < k; i++ {
					file, err := os.Stat(comArr[i+1])
					if err != nil {
						fmt.Println("ENCRYPT: Stat:", err)
						continue
					} else {
						if file.Mode().IsRegular() {
							wg.Add(1)
							go encrypt(comArr[i+1], p)
							i++
						}
					}
				}
			}
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
	fmt.Println("\t e [files] | encrypts the file or folder in the path with the password")
	fmt.Println("\t d [files] | decrypts the file or folder in the path with the password")
	fmt.Println("\t Multiple files or folders in the same directory can be encrypted or decrypted by separating them with a space.")
	fmt.Println("\t cd [path] | shows this help message")
	fmt.Println("\t ls | lists the files and folders in the path")
	fmt.Println("\t pwd | prints the current path")
	fmt.Println("\t q | quits the program")
}

func encrypt(file string, p []byte) error {
	defer wg.Done()

	key := deriveKey(p)
	fmt.Println("Encrypting ", file)

	inputFile, err := os.Open(file)
	if err != nil {
		return err
	}
	defer inputFile.Close()

	// Create the output file
	outputFile, err := os.Create(file + ".enc")
	if err != nil {
		return err
	}
	defer outputFile.Close()

	// Generate a random IV (Initialization Vector)
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return err
	}

	// Write the IV to the output file (needed for decryption)
	if _, err := outputFile.Write(iv); err != nil {
		return err
	}

	// Create the AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	// Create the GCM (Galois/Counter Mode) cipher
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	// Use GCM to encrypt the data and write it to the output file
	encrypted := aesgcm.Seal(nil, iv, []byte("This is a sample plaintext."), nil)
	if _, err := outputFile.Write(encrypted); err != nil {
		return err
	}

	inputFile.Close()
	os.Remove(inputFile.Name())

	return nil
}

func decrypt() {
}

func changeDirectory() {
}

func list() {
}

func deriveKey(o []byte) []byte {
	return pbkdf2.Key(o, []byte("useless"), 4096, 32, sha256.New)
}
