package models

import "time"

type User struct {
	ID            int64      `db:"id" json:"id"`
	Email         string     `db:"email" json:"email"`
	Username      string     `db:"username" json:"username"`
	PasswordHash  string     `db:"password_hash" json:"-"`
	FullName      string     `db:"full_name" json:"full_name"`
	IsVerified    bool       `db:"is_verified" json:"is_verified"`
	VerifyToken   *string    `db:"verify_token" json:"-"`
	VerifyExpires *time.Time `db:"verify_expires" json:"-"`

	// Cho reset password
	ResetToken   *string    `db:"reset_token" json:"-"`
	ResetExpires *time.Time `db:"reset_expires" json:"-"`
}
