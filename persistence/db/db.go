package db

import (
	"time"

	"gorm.io/gorm"
)

type DataModel struct {
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt gorm.DeletedAt `gorm:"index"`
}
