package repo

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"auth-backend/internal/models"
	"github.com/jmoiron/sqlx"
)

type UserRepo interface {
	Create(ctx context.Context, u *models.User) error
	FindByEmail(ctx context.Context, email string) (*models.User, error)
	FindByUsername(ctx context.Context, username string) (*models.User, error)

	FindByVerifyToken(ctx context.Context, token string) (*models.User, error)
	MarkVerified(ctx context.Context, id int64) error
	UpdateVerifyToken(ctx context.Context, id int64, token string, expires time.Time) error
}

type userRepo struct {
	db *sqlx.DB
}

func NewUserRepo(db *sqlx.DB) UserRepo { return &userRepo{db: db} }

func (r *userRepo) Create(ctx context.Context, u *models.User) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO users (email, username, password_hash, full_name, is_verified, verify_token, verify_expires)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		u.Email, u.Username, u.PasswordHash, u.FullName, u.IsVerified, u.VerifyToken, u.VerifyExpires,
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
	err := r.db.GetContext(ctx, &u, `
		SELECT id, email, username, password_hash, full_name, is_verified, verify_token, verify_expires
		FROM users WHERE email=? LIMIT 1`, email)
	if err != nil {
		return scanErrToNil(err)
	}
	return &u, nil
}

func (r *userRepo) FindByUsername(ctx context.Context, username string) (*models.User, error) {
	var u models.User
	err := r.db.GetContext(ctx, &u, `
		SELECT id, email, username, password_hash, full_name, is_verified, verify_token, verify_expires
		FROM users WHERE username=? LIMIT 1`, username)
	if err != nil {
		return scanErrToNil(err)
	}
	return &u, nil
}

func (r *userRepo) FindByVerifyToken(ctx context.Context, token string) (*models.User, error) {
	var u models.User
	err := r.db.GetContext(ctx, &u, `
		SELECT id, email, username, password_hash, full_name, is_verified, verify_token, verify_expires
		FROM users WHERE verify_token=? LIMIT 1`, token)
	if err != nil {
		return scanErrToNil(err)
	}
	return &u, nil
}

func (r *userRepo) MarkVerified(ctx context.Context, id int64) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE users SET is_verified=1, verify_token=NULL, verify_expires=NULL
		WHERE id=?`, id)
	return err
}

func (r *userRepo) UpdateVerifyToken(ctx context.Context, id int64, token string, expires time.Time) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE users SET verify_token=?, verify_expires=? WHERE id=?`,
		token, expires, id)
	return err
}
