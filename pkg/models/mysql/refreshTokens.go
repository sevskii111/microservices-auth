package mysql

import (
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/sevskii111/microservices-auth/pkg/models"
)

type RefreshTokenModel struct {
	DB *sql.DB
}

func (m *RefreshTokenModel) Create(userID int) (*uuid.UUID, error) {
	token, err := uuid.NewRandom()
	if err != nil {
		return nil, err
	}

	stmt := `INSERT INTO refresh_tokens (token, user_id, expires)
	VALUES(?, ?, DATE_ADD(UTC_TIMESTAMP(), INTERVAL 30 DAY))`
	_, err = m.DB.Exec(stmt, token.String(), userID)
	return &token, err
}

func (m *RefreshTokenModel) GetUserId(refreshToken string) (int, error) {
	var userID int
	var expires time.Time

	stmt := `SELECT user_id, expires FROM refresh_tokens WHERE token = ?`
	err := m.DB.QueryRow(stmt, refreshToken).Scan(&userID, &expires)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, models.ErrInvalidToken
		} else {
			return 0, err
		}
	}

	stmt = "DELETE FROM refresh_tokens WHERE token = ?"
	_, err = m.DB.Exec(stmt, refreshToken)

	if err != nil {
		return 0, err
	}

	if expires.Before(time.Now()) {
		return 0, models.ErrInvalidToken
	}

	return userID, nil
}
