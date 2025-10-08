package handlers

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/smtp"
	"os"
	"regexp"
	"strings"
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
	return &AuthHandler{users: users, jwtSecret: []byte(jwtSecret)}
}

/* ========================= helpers ========================= */

var reUpper = regexp.MustCompile(`[A-Z]`)
var reSpecial = regexp.MustCompile(`[^A-Za-z0-9]`)

func validatePassword(p string) error {
	if len(p) < 8 {
		return errors.New("password must be at least 8 characters")
	}
	if !reUpper.MatchString(p) {
		return errors.New("password must include at least one uppercase letter")
	}
	if !reSpecial.MatchString(p) {
		return errors.New("password must include at least one special character")
	}
	return nil
}

func randToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Gửi email verify: hỗ trợ 587 (STARTTLS) và 465 (implicit TLS)
func (h *AuthHandler) sendVerifyEmail(toEmail, link string) error {
	host := os.Getenv("SMTP_HOST")
	port := os.Getenv("SMTP_PORT")
	user := os.Getenv("SMTP_USER")
	pass := os.Getenv("SMTP_PASS")
	from := os.Getenv("SMTP_FROM")
	if from == "" { from = user }

	if host == "" || port == "" || user == "" || pass == "" {
		return fmt.Errorf("missing SMTP config")
	}

	subject := "Verify your email"
	body := fmt.Sprintf(
		"Hi,\r\n\r\nPlease click the link below to verify your email:\r\n%s\r\n\r\nThis link expires in 24 hours.\r\nThanks!",
		link,
	)

	// Header đầy đủ để hạn chế vào spam
	msg := []byte(
		"From: " + from + "\r\n" +
			"To: " + toEmail + "\r\n" +
			"Subject: " + subject + "\r\n" +
			"MIME-Version: 1.0\r\n" +
			"Content-Type: text/plain; charset=utf-8\r\n" +
			"Content-Transfer-Encoding: 8bit\r\n\r\n" +
			body + "\r\n",
	)

	addr := net.JoinHostPort(host, port)

	// Implicit TLS (465)
	if port == "465" {
		tlsCfg := &tls.Config{ServerName: host}
		conn, err := tls.Dial("tcp", addr, tlsCfg)
		if err != nil { return err }
		defer conn.Close()

		c, err := smtp.NewClient(conn, host)
		if err != nil { return err }
		defer c.Close()

		if err := c.Auth(smtp.PlainAuth("", user, pass, host)); err != nil { return err }
		if err := c.Mail(user); err != nil { return err }          // envelope from: dùng user
		if err := c.Rcpt(toEmail); err != nil { return err }
		w, err := c.Data()
		if err != nil { return err }
		if _, err := w.Write(msg); err != nil { _ = w.Close(); return err }
		if err := w.Close(); err != nil { return err }
		return c.Quit()
	}

	// STARTTLS (587) – Gmail chuẩn
	auth := smtp.PlainAuth("", user, pass, host)
	// envelope from: dùng user (an toàn với Gmail)
	return smtp.SendMail(addr, auth, user, []string{toEmail}, msg)
}

/* ========================= requests ========================= */

type signupReq struct {
	Email    string `json:"email"`
	Username string `json:"username"`
	Password string `json:"password"`
	FullName string `json:"full_name"`
}

type loginReq struct {
	Email    string `json:"email"` // email hoặc username
	Password string `json:"password"`
}

/* ========================= handlers ========================= */

func (h *AuthHandler) Signup(w http.ResponseWriter, r *http.Request) {
	var in signupReq
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest); return
	}
	if in.Email == "" || in.Username == "" || in.Password == "" || in.FullName == "" {
		http.Error(w, "missing fields", http.StatusBadRequest); return
	}
	if err := validatePassword(in.Password); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest); return
	}

	// Dup checks
	if e, err := h.users.FindByEmail(r.Context(), in.Email); err != nil {
		http.Error(w, "db error", http.StatusInternalServerError); return
	} else if e != nil {
		http.Error(w, "email already used", http.StatusConflict); return
	}
	if u, err := h.users.FindByUsername(r.Context(), in.Username); err != nil {
		http.Error(w, "db error", http.StatusInternalServerError); return
	} else if u != nil {
		http.Error(w, "username already used", http.StatusConflict); return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(in.Password), bcrypt.DefaultCost)
	if err != nil { http.Error(w, "hash error", http.StatusInternalServerError); return }

	tok, err := randToken(32)
	if err != nil { http.Error(w, "generate token failed", http.StatusInternalServerError); return }
	exp := time.Now().Add(24 * time.Hour)

	user := &models.User{
		Email:         in.Email,
		Username:      in.Username,
		PasswordHash:  string(hash),
		FullName:      in.FullName,
		IsVerified:    false,
		VerifyToken:   &tok,
		VerifyExpires: &exp,
	}
	if err := h.users.Create(r.Context(), user); err != nil {
		http.Error(w, "create user failed", http.StatusInternalServerError); return
	}

	verifyURL := fmt.Sprintf("%s/verify-email?token=%s", strings.TrimRight(os.Getenv("APP_BASE_URL"), "/"), tok)
	if err := h.sendVerifyEmail(in.Email, verifyURL); err != nil {
		// Nếu muốn "fail đăng ký khi gửi mail lỗi", đổi thành: http.Error(..., 500); return
		fmt.Println("sendVerifyEmail error:", err)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_, _ = w.Write([]byte(`{"message":"signup success, please verify your email"}`))
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var in loginReq
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest); return
	}

	var (
		u   *models.User
		err error
	)
	// Cho phép email hoặc username ở trường "email"
	if strings.Contains(in.Email, "@") {
		u, err = h.users.FindByEmail(r.Context(), in.Email)
	} else {
		u, err = h.users.FindByUsername(r.Context(), in.Email)
	}
	if err != nil { http.Error(w, "db error", http.StatusInternalServerError); return }
	if u == nil { http.Error(w, "invalid credentials", http.StatusUnauthorized); return }

	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(in.Password)); err != nil {
		http.Error(w, "invalid credentials", http.StatusUnauthorized); return
	}
	if !u.IsVerified {
		http.Error(w, "email not verified", http.StatusForbidden) // 403
		return
	}

	claims := jwt.MapClaims{
		"sub":      u.ID,
		"email":    u.Email,
		"username": u.Username,
		"name":     u.FullName,
		"exp":      time.Now().Add(24 * time.Hour).Unix(),
		"iss":      "auth-backend",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	ss, err := token.SignedString(h.jwtSecret)
	if err != nil { http.Error(w, "sign token failed", http.StatusInternalServerError); return }

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"token":"` + ss + `"}`))
}

/* ---------- Verify link ---------- */
// GET /auth/verify?token=xxxx
func (h *AuthHandler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" { http.Error(w, "missing token", http.StatusBadRequest); return }

	u, err := h.users.FindByVerifyToken(r.Context(), token)
	if err != nil { http.Error(w, "db error", http.StatusInternalServerError); return }
	if u == nil || u.VerifyToken == nil || *u.VerifyToken != token {
		http.Error(w, "invalid token", http.StatusBadRequest); return
	}
	if u.VerifyExpires != nil && time.Now().After(*u.VerifyExpires) {
		http.Error(w, "token expired", http.StatusBadRequest); return
	}

	if err := h.users.MarkVerified(r.Context(), u.ID); err != nil {
		http.Error(w, "verify failed", http.StatusInternalServerError); return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"message":"email verified"}`))
}

/* ---------- Resend email ---------- */
// POST /auth/resend  body: { "email": "abc@xyz.com" }
func (h *AuthHandler) ResendVerify(w http.ResponseWriter, r *http.Request) {
	var in struct{ Email string `json:"email"` }
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Email == "" {
		http.Error(w, "invalid json", http.StatusBadRequest); return
	}
	u, err := h.users.FindByEmail(r.Context(), in.Email)
	if err != nil { http.Error(w, "db error", http.StatusInternalServerError); return }
	if u == nil { http.Error(w, "email not found", http.StatusNotFound); return }
	if u.IsVerified {
		http.Error(w, "email already verified", http.StatusConflict); return
	}

	tok, err := randToken(32)
	if err != nil { http.Error(w, "generate token failed", http.StatusInternalServerError); return }
	exp := time.Now().Add(24 * time.Hour)
	if err := h.users.UpdateVerifyToken(r.Context(), u.ID, tok, exp); err != nil {
		http.Error(w, "db error", http.StatusInternalServerError); return
	}

	verifyURL := fmt.Sprintf("%s/verify-email?token=%s", strings.TrimRight(os.Getenv("APP_BASE_URL"), "/"), tok)
	if err := h.sendVerifyEmail(u.Email, verifyURL); err != nil {
		fmt.Println("sendVerifyEmail error:", err)
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"message":"verification email resent"}`))
}

/* ---------- Me + middleware ---------- */

type ctxKey string

const (
	ctxEmail    ctxKey = "email"
	ctxName     ctxKey = "name"
	ctxUsername ctxKey = "username"
	ctxUID      ctxKey = "uid"
)

func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	email, _ := r.Context().Value(ctxEmail).(string)
	name, _ := r.Context().Value(ctxName).(string)
	uname, _ := r.Context().Value(ctxUsername).(string)
	uid, _ := r.Context().Value(ctxUID).(int64)

	_ = json.NewEncoder(w).Encode(map[string]any{
		"id":        uid,
		"email":     email,
		"username":  uname,
		"full_name": name,
	})
}

func (h *AuthHandler) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bearer := r.Header.Get("Authorization")
		if len(bearer) < 8 || bearer[:7] != "Bearer " {
			http.Error(w, "missing bearer token", http.StatusUnauthorized); return
		}
		tokStr := bearer[7:]
		tok, err := jwt.Parse(tokStr, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok { return nil, os.ErrInvalid }
			return h.jwtSecret, nil
		})
		if err != nil || !tok.Valid { http.Error(w, "invalid token", http.StatusUnauthorized); return }

		claims, ok := tok.Claims.(jwt.MapClaims); if !ok {
			http.Error(w, "invalid claims", http.StatusUnauthorized); return
		}
		ctx := r.Context()
		if v, ok := claims["email"].(string); ok { ctx = context.WithValue(ctx, ctxEmail, v) }
		if v, ok := claims["name"].(string); ok { ctx = context.WithValue(ctx, ctxName, v) }
		if v, ok := claims["username"].(string); ok { ctx = context.WithValue(ctx, ctxUsername, v) }
		if v, ok := claims["sub"].(float64); ok { ctx = context.WithValue(ctx, ctxUID, int64(v)) }
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
