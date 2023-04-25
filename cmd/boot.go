package cmd

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"

	"moodle-api/pkg/httpclient"

	appConfiguration "moodle-api/app/appconf"
	"moodle-api/internal/base/handler"
	redis2 "moodle-api/internal/base/service/redisser"
	priHandler "moodle-api/internal/primary/handler"
	primaryRepo "moodle-api/internal/primary/repository"
	primaryService "moodle-api/internal/primary/service"
	"moodle-api/pkg/db"
	"moodle-api/pkg/validation"

	"github.com/go-playground/validator/v10"
	"github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var (
	appConf            *appConfiguration.Config
	baseHandler        *handler.BaseHTTPHandler
	primaryHandler     *priHandler.HTTPHandler
	redisClient        redis2.RedisClient
	postgresClientRepo *db.PostgreSQLClientRepository
	validate           *validator.Validate
	httpClient         httpclient.Client
)

// func initRedisCluster() {
// 	var ctx = context.TODO()
// 	redisHostList := strings.Split(os.Getenv("REDIS_HOST_CLUSTER"), ",")
// 	r := redis.NewClusterClient(&redis.ClusterOptions{
// 		Addrs:       redisHostList,
// 		MaxRetries:  3,
// 		DialTimeout: 10 * time.Second,
// 	})
// 	err := r.Ping(ctx).Err()
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	log.Print("Redis Cluster ping successful")
// 	redisClient = redis2.NewRedisClusterClient(r)
// }

// func initRedisSentinel() {
// 	var ctx = context.TODO()

// 	redisSentinelHost := strings.Split(os.Getenv("REDIS_SENTINEL_HOST"), ",")

// 	r := redis.NewFailoverClusterClient(&redis.FailoverOptions{
// 		MasterName:    "mymaster",
// 		SentinelAddrs: redisSentinelHost,
// 		MaxRetries:    3,
// 		DialTimeout:   10 * time.Second,

// 		// To route commands by latency or randomly, enable one of the following.
// 		RouteByLatency: true,
// 		//RouteRandomly: true,
// 	})

// 	err := r.Ping(ctx).Err()
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	log.Print("Redis Sentinel ping successful")
// }

func initRedis() {
	var ctx = context.TODO()
	rdb, _ := strconv.Atoi(os.Getenv("REDIS_DB"))
	r := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%s", os.Getenv("REDIS_HOST"), os.Getenv("REDIS_PORT")),
		Password: os.Getenv("REDIS_PASSWORD"),
		DB:       rdb,
	})

	err := r.Ping(ctx).Err()
	if err != nil {
		log.Fatal(err)
	}

	redisClient = redis2.NewRedisClient(r)
}

func initPostgreSQL() {
	host := os.Getenv("DB_HOST")
	port, _ := strconv.Atoi(os.Getenv("DB_PORT"))
	dbname := os.Getenv("DB_NAME")
	uname := os.Getenv("DB_USERNAME")
	pass := os.Getenv("DB_PASSWORD")

	var gConfig *gorm.Config
	if os.Getenv("DEV_SHOW_QUERY") == "True" {
		showQuery := logger.New(
			log.New(os.Stdout, "\r\n", log.LstdFlags),
			logger.Config{
				LogLevel: logger.Info,
			})

		gConfig = &gorm.Config{Logger: showQuery}
	} else {
		gConfig = &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)}
	}

	postgresClientRepo, _ = db.NewMPostgreSQLRepository(host, uname, pass, dbname, port, gConfig)

}

func initHTTP() {
	appConf = appConfiguration.InitAppConfig()
	initInfrastructure()

	appConf.MysqlTZ = postgresClientRepo.TZ

	baseHandler = handler.NewBaseHTTPHandler(postgresClientRepo.DB, appConf, postgresClientRepo, validate, redisClient,
		httpClient)
	primaryRepo := primaryRepo.NewRepository(postgresClientRepo.DB, postgresClientRepo)
	primaryService := primaryService.NewService(primaryRepo, httpClient)
	primaryHandler = priHandler.NewHTTPHandler(baseHandler, primaryService, redisClient)
}

func initInfrastructure() {
	// useRedisCluster := os.Getenv("USE_REDIS_CLUSTER")
	// if useRedisCluster == "true" {
	// 	// initRedisCluster()
	// 	initRedisSentinel()
	// } else if useRedisCluster == "false" {
	initRedis()
	// } else {
	// 	log.Panic("Input either true or false on USE_REDIS_CLUSTER env")
	// }
	initPostgreSQL()
	initLog()
	httpClientFactory := httpclient.New()
	httpClient = httpClientFactory.CreateClient(redisClient)
	initValidator()
}

func initValidator() {
	validate = validator.New()
	validation.ExtendValidator(validate)
}

func isProd() bool {
	return os.Getenv("APP_ENV") == "production"
}

func initLog() {
	lv := os.Getenv("LOG_LEVEL_DEV")
	level := logrus.InfoLevel
	switch lv {
	case "PanicLevel":
		level = logrus.PanicLevel
	case "FatalLevel":
		level = logrus.FatalLevel
	case "ErrorLevel":
		level = logrus.ErrorLevel
	case "WarnLevel":
		level = logrus.WarnLevel
	case "InfoLevel":
		level = logrus.InfoLevel
	case "DebugLevel":
		level = logrus.DebugLevel
	case "TraceLevel":
		level = logrus.TraceLevel
	default:
	}

	if isProd() {
		logrus.SetFormatter(&logrus.JSONFormatter{})
		logrus.SetLevel(logrus.WarnLevel)
		logrus.SetOutput(os.Stdout)
	} else {
		logrus.SetFormatter(&logrus.JSONFormatter{PrettyPrint: true})

		if lv == "" && os.Getenv("APP_DEBUG") == "True" {
			level = logrus.DebugLevel
		}
		logrus.SetLevel(level)

		if os.Getenv("DEV_FILE_LOG") == "True" {
			logfile, err := os.OpenFile("log/app.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0755)
			if err != nil {
				fmt.Printf("error opening file : %v", err)
			}

			mw := io.MultiWriter(os.Stdout, logfile)
			logrus.SetOutput(mw)
		} else {
			logrus.SetOutput(os.Stdout)
		}
	}
}
