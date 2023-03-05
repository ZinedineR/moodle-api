package cmd

import (
	"github.com/joho/godotenv"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"os"
)

var rootCmd = &cobra.Command{
	Use:   "Go Simple API",
	Short: "Go Simple API / Service Demo",
	Long:  "Go Simple API / Service Demo HTTP & GRPC API & Kafka",
	Run: func(cmd *cobra.Command, args []string) {
		_ = cmd.Help()
	},
}

//register command
func init() {
	rootCmd.AddCommand(HttpCmd)

	//load environment variable
	if err := godotenv.Load(); err != nil {
		if os.Getenv("APP_ENV") == "development" {
			logrus.Fatalln("unable to load environment variable", err.Error())
		} else {
			logrus.Warningln("Can't find env.file. To use system's env vars for now")
		}

	}
}

func Execute() error {
	cmd, _, err := rootCmd.Find(os.Args[1:])

	if err == nil && cmd.Use == rootCmd.Use && cmd.Flags().Parse(os.Args[1:]) != pflag.ErrHelp {
		args := append([]string{"http"}, os.Args[1:]...)
		rootCmd.SetArgs(args)
	}

	return rootCmd.Execute()
}
