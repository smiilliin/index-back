package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"github.com/labstack/echo/v4"
	generation "github.com/smiilliin/go-token-generation"
)

func getDB() (*sql.DB, error) {
	dbUser := os.Getenv("DB_USER")
	dbPassword := os.Getenv("DB_PASSWORD")
	dbDatabase := os.Getenv("DB_DATABASE")

	dbDSN := fmt.Sprintf("%s:%s@tcp(mariadb:3306)/%s", dbUser, dbPassword, dbDatabase)
	db, err := sql.Open("mysql", dbDSN)

	if err != nil {
		return nil, err
	}
	db.SetMaxIdleConns(3)
	db.SetMaxOpenConns(6)

	return db, nil
}

type SigninBody struct {
	ID           string `json:"id"`
	PasswordHash string `json:"password"`
	KeepLoggedin bool   `json:"keepLoggedin"`
}
type SignupBody struct {
	ID           string `json:"id"`
	PasswordHash string `json:"password"`
	KeepLoggedin bool   `json:"keepLoggedin"`
	GResponse    string `json:"gResponse"`
}

func decodeJSONBody(c echo.Context, v interface{}) error {
	return json.NewDecoder(c.Request().Body).Decode(v)
}
func idTest(id string) bool {
	pattern := regexp.MustCompile(`^[a-z0-9]{4,20}$`)
	return pattern.MatchString(id)
}
func passwordHashTest(password string) bool {
	pattern := regexp.MustCompile(`^[a-fA-F0-9]{64}$`)
	return pattern.MatchString(password)
}
func getHmcaKey() ([]byte, error) {
	content, err := os.ReadFile("/.hmac")

	if err != nil {
		return nil, err
	}

	hmacKey, err := hex.DecodeString(string(content))
	if err != nil {
		return nil, err
	}

	return hmacKey, nil
}

type RecaptchaBody struct {
	Secret    string `json:"secret"`
	GResponse string `json:"response"`
}
type RecaptchaResponse struct {
	Success    bool     `json:"success"`
	Errorcodes []string `json:"error-codes"`
}

func checkRecaptcha(recaptchaSecret string, gResponse string) (bool, error) {
	apiURL := "https://www.google.com/recaptcha/api/siteverify"
	body := fmt.Sprintf("secret=%s&response=%s", recaptchaSecret, gResponse)

	req, err := http.NewRequest("POST", apiURL, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if err != nil {
		return false, err
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	result := RecaptchaResponse{}
	err = json.NewDecoder(resp.Body).Decode(&result)

	if err != nil {
		return false, err
	}
	if !result.Success {
		fmt.Println(result.Errorcodes)
	}
	return result.Success, nil
}

type AccessResponse struct {
	Status          bool   `json:"status"`
	Access          string `json:"access"`
	RefreshLifespan int64  `json:"lifespan"`
}

func main() {
	db, err := getDB()

	if err != nil {
		log.Fatal(err)
	}

	hmacKey, err := getHmcaKey()

	if err != nil {
		log.Fatal(err)
	}

	for {
		err = db.Ping()

		if err == nil {
			break
		}

		log.Println("Wait for db")
		time.Sleep(time.Second)
	}

	cookieDomain := os.Getenv("COOKIE_DOMAIN")
	recaptchaSecret := os.Getenv("RECAPTCHA_SECRET")

	e := echo.New()

	generation.GetGeneration(db, "smile")

	e.POST("/signup", func(c echo.Context) error {
		body := SignupBody{}
		err := decodeJSONBody(c, &body)

		if err != nil {
			fmt.Println(err)
			return c.JSON(400, StatusResponse{Status: false, Reason: ReasonJSONParse})
		}

		success, err := checkRecaptcha(recaptchaSecret, body.GResponse)

		if err != nil {
			fmt.Println(err)
			return c.JSON(400, StatusResponse{Status: false, Reason: ReasonUnknown})
		}
		if !success {
			fmt.Println("Recaptcha failed")
			return c.JSON(400, StatusResponse{Status: false, Reason: ReasonRecaptchaFailed})
		}

		rows, err := db.Query("SELECT id FROM user WHERE id=?", body.ID)

		if err != nil {
			fmt.Println(err)
			return c.JSON(400, StatusResponse{Status: false, Reason: ReasonUnknown})
		}

		defer rows.Close()

		if rows.Next() {
			fmt.Println("ID is already existed")
			return c.JSON(400, StatusResponse{Status: false, Reason: ReasonIDUsing})
		}

		if !idTest(body.ID) {
			fmt.Println("ID test failed")
			return c.JSON(400, StatusResponse{Status: false, Reason: ReasonIDInvalid})
		}
		if !passwordHashTest(body.PasswordHash) {
			fmt.Println("PasswordHash test failed")
			return c.JSON(400, StatusResponse{Status: false, Reason: ReasonPasswordInvalid})
		}

		salt := make([]byte, 10)
		passwordHash := []byte(body.PasswordHash)
		rand.Read(salt)

		repeatCountBig, err := rand.Int(rand.Reader, big.NewInt(int64(10)))
		if err != nil {
			fmt.Println(err)
			return c.JSON(400, StatusResponse{Status: false, Reason: ReasonUnknown})
		}

		repeatCount := int(repeatCountBig.Int64()) + 10
		h := sha256.New()
		h.Write(append(salt, passwordHash...))
		hashResult := h.Sum(nil)

		for i := 0; i < repeatCount; i++ {
			h.Write(append(salt, hashResult[:]...))
			hashResult = h.Sum(nil)
		}
		_, err = db.Exec("INSERT INTO user VALUES(?, ?, ?, now())", body.ID, hashResult, salt)

		if err != nil {
			fmt.Println(err)
			return c.JSON(400, StatusResponse{Status: false, Reason: ReasonUnknown})
		}

		token, err := generation.CreateRefreshToken(db, body.ID, 30*24*time.Hour)

		if err != nil {
			fmt.Println(err)
			return c.JSON(400, StatusResponse{Status: false, Reason: ReasonUnknown})
		}
		tokenString, err := generation.RefreshTokenToString(token, hmacKey)

		if err != nil {
			fmt.Println(err)
			return c.JSON(400, StatusResponse{Status: false, Reason: ReasonUnknown})
		}

		cookie := new(http.Cookie)
		cookie.Name = "refresh"
		cookie.Value = tokenString
		cookie.Domain = cookieDomain
		cookie.HttpOnly = true
		cookie.Secure = true
		cookie.SameSite = http.SameSiteLaxMode

		if body.KeepLoggedin {
			cookie.Expires = time.Now().Add(30 * 24 * time.Hour)
		}
		c.SetCookie(cookie)

		return c.JSON(200, StatusResponse{Status: true, Reason: ReasonNothing})
	})
	e.POST("/signin", func(c echo.Context) error {
		body := SigninBody{}
		err := decodeJSONBody(c, &body)

		if err != nil {
			fmt.Println(err)
			return c.JSON(400, StatusResponse{Status: false, Reason: ReasonJSONParse})
		}

		time.Sleep(300 * time.Millisecond)

		rows, err := db.Query("SELECT password, salt FROM user WHERE id=?", body.ID)

		if err != nil || !rows.Next() {
			fmt.Println("No user is found")
			return c.JSON(400, StatusResponse{Status: false, Reason: ReasonInputIncorrect})
		}

		defer rows.Close()

		var (
			dbPassword []byte
			salt       []byte
		)

		err = rows.Scan(&dbPassword, &salt)

		if err != nil {
			fmt.Println(err)
			return c.JSON(400, StatusResponse{Status: false, Reason: ReasonUnknown})
		}

		passwordHash := []byte(body.PasswordHash)

		h := sha256.New()
		h.Write(append(salt, passwordHash...))
		hashResult := h.Sum(nil)
		passed := false

		for i := 0; i < 20; i++ {
			h.Write(append(salt, hashResult...))
			hashResult = h.Sum(nil)

			if bytes.Equal(hashResult, dbPassword) {
				passed = true
				break
			}
		}

		if !passed {
			fmt.Println("Password hash is not equal")
			return c.JSON(400, StatusResponse{Status: false, Reason: ReasonInputIncorrect})
		}
		token, err := generation.CreateRefreshToken(db, body.ID, 30*24*time.Hour)

		if err != nil {
			fmt.Println(err)
			return c.JSON(400, StatusResponse{Status: false, Reason: ReasonUnknown})
		}
		tokenString, err := generation.RefreshTokenToString(token, hmacKey)

		if err != nil {
			fmt.Println(err)
			return c.JSON(400, StatusResponse{Status: false, Reason: ReasonUnknown})
		}

		cookie := new(http.Cookie)
		cookie.Name = "refresh"
		cookie.Value = tokenString
		cookie.Domain = cookieDomain
		cookie.HttpOnly = true
		cookie.Secure = true
		cookie.SameSite = http.SameSiteLaxMode

		if body.KeepLoggedin {
			cookie.Expires = time.Now().Add(30 * 24 * time.Hour)
		}
		c.SetCookie(cookie)

		return c.JSON(200, StatusResponse{Status: true, Reason: ReasonNothing})
	})
	e.POST("/access", func(c echo.Context) error {
		refreshCookie, err := c.Cookie("refresh")

		if err != nil {
			return c.JSON(400, StatusResponse{Status: true, Reason: ReasonRefreshInvalid})
		}
		refreshToken, err := generation.RefreshTokenParse(refreshCookie.Value, hmacKey)

		if err != nil {
			return c.JSON(400, StatusResponse{Status: true, Reason: ReasonRefreshInvalid})
		}

		lifespan := refreshToken.Expires - time.Now().UnixMilli()

		accessToken, err := generation.CreateAccessToken(db, refreshToken, time.Hour)

		if err != nil {
			return c.JSON(400, StatusResponse{Status: true, Reason: ReasonUnknown})
		}

		access, err := generation.AccessTokenToString(accessToken, hmacKey)

		if err != nil {
			return c.JSON(400, StatusResponse{Status: true, Reason: ReasonUnknown})
		}

		return c.JSON(200, AccessResponse{Status: true, Access: access, RefreshLifespan: lifespan})
	})
	e.POST("/refresh", func(c echo.Context) error {
		refreshCookie, err := c.Cookie("refresh")

		if err != nil {
			return c.JSON(400, StatusResponse{Status: true, Reason: ReasonRefreshInvalid})
		}
		refreshToken, err := generation.RefreshTokenParse(refreshCookie.Value, hmacKey)

		if err != nil {
			return c.JSON(400, StatusResponse{Status: true, Reason: ReasonRefreshInvalid})
		}

		err = generation.UpdateRefreshToken(db, refreshToken, 30)

		if err != nil {
			return c.JSON(400, StatusResponse{Status: true, Reason: ReasonUnknown})
		}

		tokenString, err := generation.RefreshTokenToString(refreshToken, hmacKey)

		if err != nil {
			return c.JSON(400, StatusResponse{Status: true, Reason: ReasonUnknown})
		}

		cookie := new(http.Cookie)
		cookie.Name = "refresh"
		cookie.Value = tokenString
		cookie.Domain = cookieDomain
		cookie.HttpOnly = true
		cookie.Secure = true
		cookie.SameSite = http.SameSiteLaxMode
		cookie.Expires = time.Now().Add(30 * 24 * time.Hour)

		c.SetCookie(cookie)

		return c.JSON(200, StatusResponse{Status: true, Reason: ReasonNothing})
	})
	e.POST("/logout", func(c echo.Context) error {
		cookie := new(http.Cookie)
		cookie.Name = "refresh"
		cookie.Value = ""
		cookie.Domain = cookieDomain
		cookie.HttpOnly = true
		cookie.Secure = true
		cookie.SameSite = http.SameSiteLaxMode
		cookie.Expires = time.Now().Add(-3600)

		c.SetCookie(cookie)

		return c.JSON(200, StatusResponse{Status: true, Reason: ReasonNothing})
	})

	e.Logger.Fatal(e.Start(":80"))
}
