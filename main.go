package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-redis/redis/v8"
	"github.com/gofiber/fiber/v2"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/spotify"
	"math/rand"
	"os"
	"time"
	"unsafe"
)

func main() {
	authKey := os.Getenv("AUTH_KEY")

	if authKey == "" {
		fmt.Println("Service insecure, make sure AUTH_KEY is set before running in prod")
	}

	redisAddr := os.Getenv("REDIS_ADDR")
	redisAuth := os.Getenv("REDIS_AUTH")

	if redisAddr == "" {
		panic("REDIS_ADDR not defined")
	}

	spotifyClientId := os.Getenv("SPOTIFY_CLIENT_ID")
	spotifyClientSecret := os.Getenv("SPOTIFY_CLIENT_SECRET")

	if spotifyClientId == "" || spotifyClientSecret == "" {
		panic("SPOTIFY_CLIENT_ID or SPOTIFY_CLIENT_SECRET not defined")
	}

	rdb := redis.NewClient(&redis.Options{
		Addr:     redisAddr,
		Password: redisAuth,
	})

	oauthConfig := oauth2.Config{
		ClientID:     spotifyClientId,
		ClientSecret: spotifyClientSecret,
		Endpoint:     spotify.Endpoint,
		Scopes:       []string{"streaming", "user-read-playback-state", "user-modify-playback-state", "user-read-currently-playing"},
		RedirectURL:  "https://tnl.ncbr.wtf/callback",
	}
	app := fiber.New()

	app.Get("/url", func(ctx *fiber.Ctx) error {
		if auth, ok := ctx.GetReqHeaders()["Authorization"]; ok {
			if auth != authKey {
				return ctx.SendStatus(401)
			}
		} else if !ok && authKey != "" {
			return ctx.SendStatus(401)
		}

		id := ctx.Query("id")
		if id == "" {
			return ctx.SendStatus(403)
		}

		state := RandStringBytesMaskImprSrcUnsafe(5)
		status := rdb.Set(context.Background(), fmt.Sprintf("state:%s", state), id, time.Hour)
		if status.Err() != nil {
			return status.Err()
		}
		return ctx.SendString(oauthConfig.AuthCodeURL(state))
	})

	app.Get("/callback", func(ctx *fiber.Ctx) error {
		exchange, err := oauthConfig.Exchange(context.Background(), ctx.Query("code"))
		if err != nil {
			return err
		}

		state := ctx.Query("state")
		if state == "" {
			return errors.New("no state provided")
		}

		key := fmt.Sprintf("state:%s", state)
		id := rdb.Get(context.Background(), key)
		if id.Err() != nil {
			return id.Err()
		}
		rdb.Del(context.Background(), key)

		exStr, _ := json.Marshal(exchange)
		status := rdb.Set(context.Background(), fmt.Sprintf("oauth:%s", id.Val()), exStr, 0)
		if status.Err() != nil {
			return status.Err()
		}
		return ctx.SendString("You may close this tab.")
	})

	app.Get("/token", func(ctx *fiber.Ctx) error {
		if auth, ok := ctx.GetReqHeaders()["Authorization"]; ok {
			if auth != authKey {
				return ctx.SendStatus(401)
			}
		} else if !ok && authKey != "" {
			return ctx.SendStatus(401)
		}

		id := ctx.Query("id")
		if id == "" {
			return ctx.SendStatus(403)
		}

		ex := rdb.Get(context.Background(), fmt.Sprintf("oauth:%s", id))
		if ex.Err() != nil {
			return ex.Err()
		}

		var exchange oauth2.Token
		json.Unmarshal([]byte(ex.Val()), &exchange)
		token, err := oauthConfig.TokenSource(context.Background(), &exchange).Token()
		if err != nil {
			return err
		}
		return ctx.SendString(token.AccessToken)
	})

	app.Listen(":8888")
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const (
	letterIdxBits = 6
	letterIdxMask = 1<<letterIdxBits - 1
	letterIdxMax  = 63 / letterIdxBits
)

var src = rand.NewSource(time.Now().UnixNano())

func RandStringBytesMaskImprSrcUnsafe(n int) string {
	b := make([]byte, n)
	for i, cache, remain := n-1, src.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return *(*string)(unsafe.Pointer(&b))
}
