// main.go

package main

import (
	"context"
	_"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-redis/redis/v8"
	"github.com/zeromicro/go-zero/core/logx"
	"github.com/zeromicro/go-zero/rest"
	"github.com/zeromicro/go-zero/rest/httpx"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

const (
	redisSessionPrefix = "session:"
	redisSessionExpire = time.Hour * 24 * 7 // Redis session expiration time (7 days)
	redisKeyPrefix     = "user:"
	redisKeyExpire     = time.Hour * 24    // Redis key expiration time (1 day)
	secretKey          = "your_secret_key" // Replace with your own secret key for JWT
)

type User struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Token string `json:"token"`
}

type UserInfoResponse struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
}

var (
	redisClient *redis.Client
	db          *gorm.DB
)

func main() {
	redisClient = redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
	})
	defer redisClient.Close()

	db, err := gorm.Open(mysql.Open("user:password@tcp(localhost:3306)/database"), &gorm.Config{})
	if err != nil {
		logx.Fatalf("failed to connect to database: %v", err)
	}
	db.AutoMigrate(&User{})

	ctx := svc.NewServiceContext()

	router := rest.MustNewServer(rest.RestConf{
		Port: 8080,
	})
	defer router.Stop()

	router.AddRoute(rest.Route{
		Method: http.MethodPost,
		Path:   "/login",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			loginHandler(ctx).ServeHTTP(w, r)
		}),
	})

	router.AddRoute(rest.Route{
		Method: http.MethodGet,
		Path:   "/user-info",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			getUserInfoHandler(ctx).ServeHTTP(w, r)
		}),
	})

	logx.Infof("Server is running on http://localhost:%d", 8080)
	router.Start()
}

func loginHandler(ctx context.Context) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req LoginRequest
		err := httpx.Parse(r, &req)
		if err != nil {
			httpx.Error(w, err)
			return
		}

		user, err := findUserByUsernameAndPassword(ctx, req.Username, req.Password)
		if err != nil {
			httpx.Error(w, errors.New("invalid username or password"))
			return
		}

		token, err := generateToken(user)
		if err != nil {
			httpx.Error(w, err)
			return
		}

		err = createRedisSession(ctx, user.ID, token)
		if err != nil {
			httpx.Error(w, err)
			return
		}

		httpx.OkJson(w, LoginResponse{Token: token})
	}
}

func findUserByUsernameAndPassword(ctx context.Context, username, password string) (*User, error) {
	var user User
	if err := db.Where("username = ? AND password = ?", username, password).First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

func generateToken(user *User) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["id"] = user.ID
	claims["username"] = user.Username
	claims["exp"] = time.Now().Add(time.Hour * 24).Unix() // Token hết hạn sau 1 ngày
	signedToken, err := token.SignedString([]byte(secretKey))
	if err != nil {
		return "", err
	}
	return signedToken, nil
}

func createRedisSession(ctx context.Context, userID int64, token string) error {
	sessionKey := redisSessionPrefix + token
	userKey := redisKeyPrefix + string(userID)
	pipe := redisClient.Pipeline()
	pipe.Set(ctx, sessionKey, userID, redisSessionExpire)
	pipe.Set(ctx, userKey, token, redisKeyExpire)
	_, err := pipe.Exec(ctx)
	return err
}

func getUserInfoHandler(ctx context.Context) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			httpx.Error(w, errors.New("missing authorization header"))
			return
		}

		authHeaderParts := strings.Split(authHeader, " ")
		if len(authHeaderParts) != 2 || authHeaderParts[0] != "Bearer" {
			httpx.Error(w, errors.New("invalid authorization header format"))
			return
		}

		tokenString := authHeaderParts[1]
		claims, err := validateToken(tokenString)
		if err != nil {
			httpx.Error(w, err)
			return
		}

		userID, ok := claims["id"].(float64)
		if !ok {
			httpx.Error(w, errors.New("invalid user ID in token claims"))
			return
		}

		userInfo := UserInfoResponse{
			ID:       int64(userID),
			Username: claims["username"].(string),
		}

		httpx.OkJson(w, userInfo)
	}
}

func validateToken(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("invalid signing method")
		}
		return []byte(secretKey), nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}

	return claims, nil
}
