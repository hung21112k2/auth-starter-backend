package repo

import (
	"context"
	"database/sql"
	"errors"

	"auth-backend/internal/models"
	"github.com/jmoiron/sqlx"
)

type UserRepo interface {
	Create(ctx context.Context, u *models.User) error
	FindByEmail(ctx context.Context, email string) (*models.User, error)
	FindByUsername(ctx context.Context, username string) (*models.User, error)
}

type userRepo struct {
	db *sqlx.DB
}

func NewUserRepo(db *sqlx.DB) UserRepo {
	return &userRepo{db: db}
}

func (r *userRepo) Create(ctx context.Context, u *models.User) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO users (email, username, password_hash, full_name) VALUES (?, ?, ?, ?)`,
		u.Email, u.Username, u.PasswordHash, u.FullName,
	)
	return err
}

func scanErrToNil(err error) (*models.User, error) {
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return nil, err
}

func (r *userRepo) FindByEmail(ctx context.Context, email string) (*models.User, error) {
	var u models.User
	err := r.db.GetContext(ctx, &u,
		`SELECT id, email, username, password_hash, full_name FROM users WHERE email=? LIMIT 1`,
		email,
	)
	if err != nil {
		return scanErrToNil(err)
	}
	return &u, nil
}

func (r *userRepo) FindByUsername(ctx context.Context, username string) (*models.User, error) {
	var u models.User
	err := r.db.GetContext(ctx, &u,
		`SELECT id, email, username, password_hash, full_name FROM users WHERE username=? LIMIT 1`,
		username,
	)
	if err != nil {
		return scanErrToNil(err)
	}
	return &u, nil
}
