package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/2tvenom/golifx"
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

type reward int8

const (
	lights reward = iota
	endStream
	silenceMe
	premium
	scrollo
	unknown
)

func rewardFromString(s string) reward {
	switch s {
	case "lights":
		return lights
	case "end the stream":
		return endStream
	case "silence me":
		return silenceMe
	case "SimpBucks Premium":
		return premium
	case "scrollo":
		return scrollo
	default:
		return unknown
	}
}

type hmacKey struct {
	secret      []byte
	permissions []reward
}

var ceilingBulb, bedBulb *golifx.Bulb

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

func verifyWebhook(r *http.Request, requestBody []byte, hmacKeys []hmacKey) []reward {
	signatures, err := getCoolHeader("Twitch-Eventsub-Message-Signature", r)
	if err != nil {
		log.Println(err)
		return nil
	}
	splitSignature := strings.SplitN(signatures, "=", 2)
	if len(splitSignature) != 2 {
		log.Println("malformed signature")
		return nil
	}

	hexSignature := splitSignature[1]
	signature, err := hex.DecodeString(hexSignature)
	if err != nil {
		log.Println("malformed signature: could not decode hex")
		return nil
	}

	timestamp, err := getCoolHeader("Twitch-Eventsub-Message-Timestamp", r)
	if err != nil {
		log.Println(err)
		return nil
	}

	msgId, err := getCoolHeader("Twitch-Eventsub-Message-Id", r)
	if err != nil {
		log.Println(err)
		return nil
	}
	for _, hmacKey := range hmacKeys {
		calculatedHMAC := hmac.New(sha256.New, hmacKey.secret)
		calculatedHMAC.Write([]byte(msgId))
		calculatedHMAC.Write([]byte(timestamp))
		calculatedHMAC.Write(requestBody)
		expectedMAC := calculatedHMAC.Sum(nil)
		if hmac.Equal(expectedMAC, signature) {
			return hmacKey.permissions
		}
	}
	return nil
}

func lightsReward(params string) {
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
	bulb.SetColorState(col, 1)
}

func endStreamReward() {
	log.Print("killing stream")
	cmd := exec.Command("killall", "obs")
	cmd.Run()
}

func silenceMeReward() {
	log.Print("ur muted")
	cmd := exec.Command("./silencethot.sh")
	go cmd.Run()
}

func premiumReward() {
	chance := rand.Intn(10)
	sound := "woof.mp3"
	if chance == 5 {
		sound = "bark.mp3"
	}
	cmd := exec.Command("play", sound)
	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, "AUDIODEV=hw:1,0")
	go cmd.Run()
}

func scrolloReward(params string) {
	f, err := os.Create("scrollo.txt")
	if err != nil {
		log.Printf("failed to create file: %s", err)
		return
	}
	defer f.Close()
	f.WriteString(fmt.Sprintf(" %.256s ✨✨✨ ", params))
}

func unknownReward(reward string) {
	log.Printf("request for unknown reward %s", reward)
}

func handleWebhook(w http.ResponseWriter, r *http.Request) {
	requestBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Println("failed to read body", err)
		return
	}

	domKey := hmacKey{[]byte(os.Getenv("dom_secret")), []reward{lights, scrollo, unknown}}
	subKey := hmacKey{[]byte(os.Getenv("sub_secret")), []reward{lights, endStream, silenceMe, premium, scrollo, unknown}}
	hmacKeys := []hmacKey{domKey, subKey}
	permissions := verifyWebhook(r, requestBody, hmacKeys)
	if permissions == nil {
		log.Println("failed to verify signature")
		w.Write([]byte("hi cutie!"))
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
		w.Write([]byte(payload.Challenge))
		return
	}
	if msgType == "notification" {
		reward := rewardFromString(payload.Event.Reward.Title)
		params := payload.Event.UserInput
		rewardInPermissions := false
		for _, allowed := range permissions {
			if reward == allowed {
				rewardInPermissions = true
				break
			}
		}
		if !rewardInPermissions {
			log.Print("reward requested not in authorised rewards")
			return
		}
		switch reward {
		case lights:
			lightsReward(params)
		case endStream:
			endStreamReward()
		case silenceMe:
			silenceMeReward()
		case premium:
			premiumReward()
		case scrollo:
			scrolloReward(params)
		case unknown:
			unknownReward(payload.Event.Reward.Title)
		}
		return
	}
	log.Printf("got something else! %s", msgType)
}

func main() {
	log.Println("finding bulbs")
	for i := 0; i < 3; i++ {
		bulbs, err := golifx.LookupBulbs()
		if err != nil {
			log.Fatalf("failed to find bulbs! %s", err)
			return
		}
		for _, bulb := range bulbs {
			mac := bulb.MacAddress()
			if mac == "d0:73:d5:64:76:ac" {
				ceilingBulb = bulb
			} else if mac == "d0:73:d5:66:d5:ec" {
				bedBulb = bulb
			}
		}
		if ceilingBulb != nil && bedBulb != nil {
			break
		}
	}

	if ceilingBulb == nil || bedBulb == nil {
		log.Fatalf("missing bulb(s)")
	}

	log.Println("starting server")
	http.HandleFunc("/webhook", handleWebhook)
	log.Fatal(http.ListenAndServeTLS(":6969", "cert/config/live/cardassia.jacqueline.id.au/fullchain.pem", "cert/config/live/cardassia.jacqueline.id.au/privkey.pem", nil))
}
