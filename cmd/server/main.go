package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"auth-backend/internal/handlers"
	"auth-backend/internal/repo"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	_ "github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
	"github.com/joho/godotenv"
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using system environment")
	}

	port := os.Getenv("PORT"); if port == "" { port = "8080" }
	dsn := os.Getenv("DB_DSN"); if dsn == "" { log.Fatal("DB_DSN is empty") }
	secret := os.Getenv("JWT_SECRET"); if secret == "" { log.Fatal("JWT_SECRET is empty") }

	db, err := sqlx.Connect("mysql", dsn)
	if err != nil { log.Fatalf("cannot connect DB: %v", err) }
	db.SetMaxOpenConns(25); db.SetMaxIdleConns(25); db.SetConnMaxIdleTime(0)

	userRepo := repo.NewUserRepo(db)
	auth := handlers.NewAuthHandler(userRepo, secret)

	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))

	// Public
	r.Route("/auth", func(r chi.Router) {
		r.Post("/signup", auth.Signup)
		r.Post("/login", auth.Login)
		r.Get("/verify", auth.VerifyEmail)   // ?token=
		r.Post("/resend", auth.ResendVerify) // { email }
		// Forgot / Reset
		r.Post("/forgot", auth.ForgotPassword)
		r.Post("/reset",  auth.ResetPassword)
	})

	// Protected
	r.Group(func(pr chi.Router) {
		pr.Use(auth.AuthMiddleware)
		pr.Get("/auth/me", auth.Me)
	})

	log.Printf("Server running at :%s ...", port)
	log.Fatal(http.ListenAndServe(":"+port, r))
}
