package db

import (
	"database/sql"
	"fmt"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/uptrace/opentelemetry-go-extra/otelgorm"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"os"
	"strconv"
	"time"
)

type PostgreSQLClientRepository struct {
	DB *gorm.DB
	TZ string
}

func NewMPostgreSQLRepository(host, uname, pass, dbname string, port int, config *gorm.Config) (*PostgreSQLClientRepository, error) {
	tz := "Asia/Jakarta"

	if config == nil {
		config = &gorm.Config{}
	}
	maxIdleConn, _ := strconv.Atoi(os.Getenv("DB_MAX_IDLE_CONNECTION"))
	lifetimeConn, _ := time.ParseDuration(os.Getenv("DB_MAX_LIFETIME_CONNECTION"))
	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%d sslmode=disable TimeZone=%s", host, uname, pass, dbname, port, tz)
	sqlDB, err := sql.Open("pgx", dsn)

	sqlDB.SetMaxIdleConns(maxIdleConn)
	sqlDB.SetConnMaxLifetime(lifetimeConn)

	db, err := gorm.Open(postgres.New(postgres.Config{Conn: sqlDB}), config)

	db.Use(otelgorm.NewPlugin())

	if err != nil {
		logrus.Error(fmt.Sprintf("Cannot connect to PostgresSQL. %v", err))
		return nil, errors.Wrap(err, "Cannot connect to PostgresSQL")
	}

	if db == nil {
		panic("missing db")
	}

	return &PostgreSQLClientRepository{DB: db, TZ: tz}, nil

}
