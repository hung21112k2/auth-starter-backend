package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"time"

	"auth-backend/internal/models"
	"auth-backend/internal/repo"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

type AuthHandler struct {
	users     repo.UserRepo
	jwtSecret []byte
}

func NewAuthHandler(users repo.UserRepo, jwtSecret string) *AuthHandler {
	return &AuthHandler{
		users:     users,
		jwtSecret: []byte(jwtSecret),
	}
}

type signupReq struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	FullName string `json:"full_name"`
}

type loginReq struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (h *AuthHandler) Signup(w http.ResponseWriter, r *http.Request) {
	var in signupReq
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if in.Email == "" || in.Password == "" || in.FullName == "" {
		http.Error(w, "missing fields", http.StatusBadRequest)
		return
	}

	// Check duplicate
	existed, err := h.users.FindByEmail(r.Context(), in.Email)
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	if existed != nil {
		http.Error(w, "email already used", http.StatusConflict)
		return
	}

	// Hash password
	hash, err := bcrypt.GenerateFromPassword([]byte(in.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "hash error", http.StatusInternalServerError)
		return
	}

	user := &models.User{
		Email:        in.Email,
		PasswordHash: string(hash),
		FullName:     in.FullName,
	}
	if err := h.users.Create(r.Context(), user); err != nil {
		http.Error(w, "create user failed", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	_, _ = w.Write([]byte(`{"message":"signup success"}`))
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var in loginReq
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	u, err := h.users.FindByEmail(r.Context(), in.Email)
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	if u == nil {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(in.Password)); err != nil {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	// Create JWT
	claims := jwt.MapClaims{
		"sub":   u.ID,
		"email": u.Email,
		"name":  u.FullName,
		"exp":   time.Now().Add(24 * time.Hour).Unix(),
		"iss":   "auth-backend",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	ss, err := token.SignedString(h.jwtSecret)
	if err != nil {
		http.Error(w, "sign token failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"token":"` + ss + `"}`))
}

// ==== typed context keys ====
type ctxKey string

const (
	ctxEmail ctxKey = "email"
	ctxName  ctxKey = "name"
	ctxUID   ctxKey = "uid"
)

func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	email, _ := r.Context().Value(ctxEmail).(string)
	name, _ := r.Context().Value(ctxName).(string)
	uid, _ := r.Context().Value(ctxUID).(int64)

	resp := map[string]any{
		"id":        uid,
		"email":     email,
		"full_name": name,
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// ==== Middleware parse JWT ====
func (h *AuthHandler) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bearer := r.Header.Get("Authorization")
		// Expect: "Bearer <token>"
		if len(bearer) < 8 || bearer[:7] != "Bearer " {
			http.Error(w, "missing bearer token", http.StatusUnauthorized)
			return
		}
		tokenStr := bearer[7:]

		tok, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, os.ErrInvalid
			}
			return h.jwtSecret, nil
		})
		if err != nil || !tok.Valid {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}

		claims, ok := tok.Claims.(jwt.MapClaims)
		if !ok {
			http.Error(w, "invalid claims", http.StatusUnauthorized)
			return
		}

		// attach to context
		ctx := r.Context()
		if v, ok := claims["email"].(string); ok {
			ctx = context.WithValue(ctx, ctxEmail, v)
		}
		if v, ok := claims["name"].(string); ok {
			ctx = context.WithValue(ctx, ctxName, v)
		}
		if v, ok := claims["sub"].(float64); ok {
			ctx = context.WithValue(ctx, ctxUID, int64(v))
		}

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
