package db

import (
	"time"

	"gorm.io/gorm"
)

type Database interface {
	DB() *gorm.DB
}

type DataModel struct {
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt gorm.DeletedAt `gorm:"index"`
}
