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
		err = file.Chmod(0640)
		if err != nil {
			log.Fatalf("Error with os.Chmod(): %v", err)
		}
		return file
	} else {
		file, err := os.OpenFile(name, os.O_RDWR, os.FileMode(0666))
		if err != nil {
			log.Fatalf("Error with os.Open(): %v", err)
		}
		return file
	}
}

func (daemon *Daemon) loadDigestAuth(realm string) auth.DigestAuth {
	file := loadOrCreateDigestFile(".sploit-digest")
	// Setup string to hash through md5
	bytes := []byte(daemon.config.Username)
	bytes = append(bytes, []byte(":")...)
	bytes = append(bytes, []byte(realm)...)
	bytes = append(bytes, []byte(":")...)
	bytes = append(bytes, []byte(daemon.config.Password)...)
	encryptedBytePassArray := md5.Sum(bytes)
	encryptedBytePass := encryptedBytePassArray[:]
	// Setup bytes to write to htdigest file
	bytes = []byte(daemon.config.Username)
	bytes = append(bytes, []byte(":")...)
	bytes = append(bytes, []byte(realm)...)
	bytes = append(bytes, []byte(":")...)
	bytes = append(bytes, []byte(fmt.Sprintf("%x", encryptedBytePass))...)
	bytes = append(bytes, []byte("\n")...)
	_, err := file.Write(bytes)
	if err != nil {
		log.Fatalf("Error with file.Write(): %v", err)
	}
	defer file.Close()
	log.Debug("Digest File %s (re)created", file.Name())
	secretProvider := auth.HtdigestFileProvider(file.Name())
	digestAuth := auth.NewDigestAuthenticator(realm, secretProvider)
	return *digestAuth
}
