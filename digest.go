package main

import (
	"crypto/md5"
	"fmt"
	auth "github.com/abbot/go-http-auth"
	"os"
)

func loadOrCreateDigestFile(name string) *os.File {
	if _, err := os.Stat(name); os.IsNotExist(err) {
		file, err := os.Create(name)
		if err != nil {
			log.Fatalf("Error with os.Create(): %v", err)
		}
		return file
	} else {
		file, err := os.Open(name)
		if err != nil {
			log.Fatalf("Error with os.Open(): %v", err)
		}
		return file
	}
}

func (daemon *Daemon) loadDigestAuth(realm string) auth.DigestAuth {
	file := loadOrCreateDigestFile(".sploit-digest")
	info, _ := file.Stat()
	if info.Size() == 0 {
		log.Debug("Digest File is empty, creating it.")
		// Setup string to hash through md5
		byteContents := []byte(daemon.config.Username)
		byteContents = append(byteContents, []byte(":")...)
		byteContents = append(byteContents, []byte(realm)...)
		byteContents = append(byteContents, []byte(":")...)
		byteContents = append(byteContents, []byte(daemon.config.Password)...)
		encryptedBytePassArray := md5.Sum(byteContents)
		encryptedBytePass := encryptedBytePassArray[:]
		// Setup bytes to write to htdigest file
		byteContents = []byte(daemon.config.Username)
		byteContents = append(byteContents, []byte(":")...)
		byteContents = append(byteContents, []byte(realm)...)
		byteContents = append(byteContents, []byte(":")...)
		byteContents = append(byteContents, []byte(fmt.Sprintf("%x", encryptedBytePass))...)
		byteContents = append(byteContents, []byte("\n")...)
		_, err := file.Write(byteContents)
		if err != nil {
			log.Fatalf("Error with file.Write(): %v", err)
		}
		file.Close()
	} else {
		log.Debug("Digest File %s loaded", file.Name())
	}
	secretProvider := auth.HtdigestFileProvider(file.Name())
	digestAuth := auth.NewDigestAuthenticator(realm, secretProvider)
	return *digestAuth
}
