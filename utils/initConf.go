package utils

import (
	"encoding/json"
	"log"
	"os"
	"sync"
)

/*
	{
	  "token": "你的toke",
	  "receiverId": "企业id",
	  "encodingAeskey": "你的encodingAeskey"
	}
*/
type Config struct {
	Token          string `json:"token"`
	ReceiverId     string `json:"receiver_id"`
	EncodingAeskey string `json:"encoding_aeskey"`
	Port           int    `json:"port"`
}

var config *Config
var once sync.Once

func LoadConfig() *Config {

	once.Do(func() {
		config = &Config{}
		f, err := os.Open("config.json")
		if err != nil {
			log.Fatalf("open config.json err: %v\n", err)
		}
		defer f.Close()

		decoder := json.NewDecoder(f)
		if err := decoder.Decode(config); err != nil {
			log.Fatalf("decoder config err: %v\n", err)
		}
	})

	return config
}
