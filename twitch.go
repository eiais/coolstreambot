package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"hash/crc32"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/2tvenom/golifx"
	"golang.org/x/sync/errgroup"
)

type RewardJson struct {
	Title string `json:"title"`
}

type EventJson struct {
	UserInput string     `json:"user_input"`
	Reward    RewardJson `json:"reward"`
}

type PayloadJson struct {
	Challenge string    `json:"challenge"`
	Event     EventJson `json:"event"`
}

var ceilingBulb, bedBulb *golifx.Bulb

var obsScrolloFile = "scrollo.txt"

func getCoolHeader(name string, r *http.Request) (string, error) {
	val, ok := r.Header[name]
	if !ok {
		return "", fmt.Errorf("missing header %s", name)
	}
	if len(val) != 1 {
		return "", errors.New("too many headers")
	}
	return val[0], nil
}

func verifyWebhook(r *http.Request, requestBody []byte, hmacKeys [][]byte) bool {
	signatures, err := getCoolHeader("Twitch-Eventsub-Message-Signature", r)
	if err != nil {
		log.Println(err)
		return false
	}
	splitSignature := strings.SplitN(signatures, "=", 2)
	if len(splitSignature) != 2 {
		log.Println("malformed signature")
		return false
	}

	method, hexSignature := splitSignature[0], splitSignature[1]
	signature, err := hex.DecodeString(hexSignature)
	if err != nil {
		log.Println("malformed signature: could not decode hex")
		return false
	}

	var hasher func() hash.Hash
	switch method {
	case "sha1":
		hasher = sha1.New
	case "sha256":
		hasher = sha256.New
	case "sha384":
		hasher = sha512.New384
	case "sha512":
		hasher = sha512.New
	default:
		log.Println("unknown signature algorithm", method)
		return false
	}

	timestamp, err := getCoolHeader("Twitch-Eventsub-Message-Timestamp", r)
	if err != nil {
		log.Println(err)
		return false
	}

	msgId, err := getCoolHeader("Twitch-Eventsub-Message-Id", r)
	if err != nil {
		log.Println(err)
		return false
	}
	for _, hmacKey := range hmacKeys {
		calculatedHMAC := hmac.New(hasher, hmacKey)
		calculatedHMAC.Write([]byte(msgId))
		calculatedHMAC.Write([]byte(timestamp))
		calculatedHMAC.Write(requestBody)
		expectedMAC := calculatedHMAC.Sum(nil)
		if hmac.Equal(expectedMAC, signature) {
			return true
		}
	}
	return false
}

func handleWebhook(w http.ResponseWriter, r *http.Request) {
	requestBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Println("failed to read body", err)
		return
	}

	hmacKeys := [][]byte{[]byte(os.Getenv("dom_secret")), []byte(os.Getenv("sub_secret"))}
	if !verifyWebhook(r, requestBody, hmacKeys) {
		log.Println("failed to verify signature")
		_, err := w.Write([]byte("you're my good puppy\n"))
		if err != nil {
			log.Printf("failed to call kathryn a good puppy: %s", err)
			return
		}
		return
	}

	msgType, err := getCoolHeader("Twitch-Eventsub-Message-Type", r)
	if err != nil {
		log.Println(err)
		return
	}

	var payload PayloadJson
	err = json.NewDecoder(bytes.NewReader(requestBody)).Decode(&payload)
	if err != nil {
		log.Println("bad body", err)
		return
	}
	if msgType == "webhook_callback_verification" {
		log.Printf("got verification callback, challenge %s", payload.Challenge)
		_, err := w.Write([]byte(payload.Challenge))
		if err != nil {
			log.Printf("failed to write webhook challenge: %s", err)
			return
		}
		return
	}
	if msgType == "notification" {
		reward := payload.Event.Reward.Title
		params := payload.Event.UserInput
		asyncErrs := new(errgroup.Group)
		if reward == "lights" {
			number, err := strconv.ParseUint(params, 10, 64)
			if err != nil {
				hasher := crc32.NewIEEE()
				hasher.Write([]byte(params))
				number = uint64(hasher.Sum32())
			}
			whichBulb := (number / 65535) % 2
			bulb := []*golifx.Bulb{bedBulb, ceilingBulb}[whichBulb]
			hue := number % 65535
			col := &golifx.HSBK{
				Hue:        uint16(hue),
				Saturation: 65535,
				Brightness: 65535,
				Kelvin:     3200,
			}
			log.Printf("setting bulb %d to %d", whichBulb, hue)
			err = bulb.SetColorState(col, 1)
			if err != nil {
				log.Printf("failed to set color light color state: %s", err)
				return
			}
		} else if reward == "end the stream" {
			log.Print("killing stream")
			cmd := exec.Command("killall", "obs")
			asyncErrs.Go(cmd.Run)
		} else if reward == "silence me" {
			log.Print("ur muted")
			cmd := exec.Command("./silencethot.sh")
			asyncErrs.Go(cmd.Run)
		} else if reward == "SimpBucks Premium" {
			chance := rand.Intn(10)
			sound := "woof.mp3"
			if chance == 5 {
				sound = "bark.mp3"
			}
			cmd := exec.Command("play", sound)
			cmd.Env = os.Environ()
			cmd.Env = append(cmd.Env, "AUDIODEV=hw:1,0")
			asyncErrs.Go(cmd.Run)
		} else if reward == "scrollo" {
			hasher := crc32.NewIEEE()
			hasher.Write([]byte(params))
			scrolloHash := strconv.FormatUint(uint64(hasher.Sum32()), 10)
			scrolloFile := filepath.Join(".scrollocache/", scrolloHash)
			if _, err := os.Stat(scrolloFile); os.IsNotExist(err) {
				// only create the file if it doesn't exist
				f, err := os.Create(scrolloFile)
				if err != nil {
					log.Printf("failed to create file: %s", err)
					return
				}
				defer f.Close()
				_, err = f.WriteString(fmt.Sprintf(" %.256s ✨✨✨ ", params))
				if err != nil {
					log.Printf("failed to cwrite text to scrollogfile: %s", err)
					return
				}

			} else if err != nil {
				log.Printf("file in unknown state: %s", err)
				return
			}
			err = os.Link(scrolloFile, obsScrolloFile)
			if err != nil {
				log.Printf("failed to link file: %s", err)
				return
			}
		}
		if err := asyncErrs.Wait(); err != nil {
			log.Printf("async failure first err:, %s", err)
			return
		}
		return
	}
	log.Printf("got something else! %s", msgType)
}

func main() {
	log.Println("finding bulbs")
	bulbs, err := golifx.LookupBulbs()
	if err != nil {
		log.Fatalf("failed to find bulbs! %s", err)
		return
	}
	for _, bulb := range bulbs {
		mac := bulb.MacAddress()
		if mac == "d0:73:d5:64:76:ac" {
			log.Println("found ceiling bulb")
			ceilingBulb = bulb
		} else if mac == "d0:73:d5:66:d5:ec" {
			log.Println("found bed bulb")
			bedBulb = bulb
		}
	}
	if ceilingBulb == nil || bedBulb == nil {
		log.Fatalf("missing bulb(s). bulbs: %s %s", ceilingBulb, bedBulb)
	}

	log.Println("starting server")
	http.HandleFunc("/webhook", handleWebhook)
	log.Fatal(http.ListenAndServeTLS(":6969", "cert/config/live/cardassia.jacqueline.id.au/fullchain.pem", "cert/config/live/cardassia.jacqueline.id.au/privkey.pem", nil))
}
