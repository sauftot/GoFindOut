package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
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
	c := true
	for c {
		fmt.Print("GoFindOut> ")
		var command string
		fmt.Scanln(&command)
		c = handleCommand(command)
	}
}

func welcome() {
	fmt.Println("Welcome to GoFindOut, a simple tool to encrypt/decrypt your files and folders.")
	help()
}

func handleCommand(in string) bool {
	comArr := strings.Split(in, " ")
	switch strings.ToLower(comArr[0]) {
	case "h":
		help()
	case "e":
		k := len(comArr)
		if k < 2 {
			fmt.Println("Not enough arguments. Use help for a list of commands")
			return false
		}
		fmt.Println("Enter your password: ")
		p, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			fmt.Println("ENCRYPT: ReadPassword:", err)
			return false
		}
		if k == 2 && comArr[1] == "*" {
			files, err := os.ReadDir(path)
			if err != nil {
				fmt.Println("ENCRYPT: ReadDir:", err)
				return false
			}

			for _, file := range files {
				// Check if it's a regular file (not a directory)
				if file.Type().IsRegular() && !file.IsDir() {
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

	case "cd":
		changeDirectory()
	case "ls":
		list()
	case "pwd":
		fmt.Println(path)
	case "q":
		return false
	default:
		fmt.Println("Unknown. Use help for a list of commands")
	}

	return true
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

func decrypt(file string, p []byte) error {
	defer wg.Done()

	key := deriveKey(p)
	fmt.Println("Decrypting ", file)

	inputFile, err := os.Open(file)
	if err != nil {
		return err
	}
	defer inputFile.Close()

	// Create the output file
	outputFile, err := os.Create(strings.TrimSuffix(file, ".enc"))
	if err != nil {
		return err
	}
	defer outputFile.Close()

	// Read the Initialization Vector (IV) from the beginning of the ciphertext
	iv := make([]byte, aes.BlockSize)
	if _, err := inputFile.Read(iv); err != nil {
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

	// Read the rest of the ciphertext (encrypted data)
	ifile, err := os.Stat(strings.TrimSuffix(file, ".enc"))
	ifilesize := ifile.Size()
	ciphertext := make([]byte, aesgcm.Overhead()+int(ifilesize))
	if _, err := inputFile.Read(ciphertext); err != nil {
		return err
	}

	// Decrypt the ciphertext and write the decrypted data to the output file
	plaintext, err := aesgcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return err
	}

	if _, err := outputFile.Write(plaintext); err != nil {
		return err
	}

	return nil

}

func changeDirectory() {
}

func list() {
}

func deriveKey(o []byte) []byte {
	return pbkdf2.Key(o, []byte("useless"), 4096, 32, sha256.New)
}
