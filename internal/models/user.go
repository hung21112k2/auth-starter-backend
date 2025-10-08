package models

type User struct {
	ID           int64  `db:"id" json:"id"`
	Email        string `db:"email" json:"email"`
	Username     string `db:"username" json:"username"`
	PasswordHash string `db:"password_hash" json:"-"`
	FullName     string `db:"full_name" json:"full_name"`
}
