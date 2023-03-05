package appconf

import (
	"os"
	"path"
	"runtime"
)

type Config struct {
	AppEnv      string
	AppDebug    string
	AppVersion  string
	AppName     string
	AppDir      string
	TemplateDir string
	MysqlTZ     string
}

func (c Config) IsStaging() bool {
	return c.AppEnv == "development"
}

func (c Config) IsProd() bool {
	return c.AppEnv == "production"
}

func (c Config) IsDebug() bool {
	return c.AppDebug == "True"
}

func InitAppConfig() *Config {

	c := Config{}
	c.AppEnv = os.Getenv("APP_ENV")
	c.AppDebug = os.Getenv("APP_DEBUG")
	c.AppVersion = os.Getenv("APP_VERSION")
	c.AppName = os.Getenv("APP_NAME")

	_, b, _, _ := runtime.Caller(0)
	appDir := path.Join(path.Dir(b), "..")
	c.AppDir = appDir
	c.TemplateDir = appDir + "/internal/template"

	return &c

}
