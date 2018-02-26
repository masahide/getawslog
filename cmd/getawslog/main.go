package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs/cloudwatchlogsiface"
	"github.com/go-ini/ini"
	"github.com/kelseyhightower/envconfig"
	"github.com/mitchellh/go-homedir"
)

const (
	credPath = ".aws/credentials"
	confPath = ".aws/config"

	iniRoleARN    = "role_arn"
	iniSrcProfile = "source_profile"
	iniRegion     = "region"
	//appName       = "getawslog"
)

type environments struct {
	AWSSharedCredentialsFile string `envconfig:"AWS_SHARED_CREDENTIALS_FILE"`
	AWSConfigFile            string `envconfig:"AWS_CONFIG_FILE"`
	AWSDefaultProfile        string `envconfig:"AWS_DEFAULT_PROFILE"`
	AWSProfile               string `envconfig:"AWS_PROFILE"`
	AWSDefaultRegion         string `envconfig:"AWS_DEFAULT_REGION"`
	Home                     string `envconfig:"HOME"`
	PrintTime                bool   `envconfig:"PRINT_TIME" default:"false"`
	StartTime                Time   `envconfig:"START_TIME"`
	EndTime                  Time   `envconfig:"END_TIME"`
	LogStream                string `envconfig:"LOG_STREAM"`
	LogGroup                 string `envconfig:"LOG_GROUP"`
}

// Time envconfig type of time
type Time time.Time

// Decode envconfig time decoder
func (t *Time) Decode(value string) error {
	tm, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return err
	}
	*t = Time(tm)
	return err
}

type profileConfig struct {
	RoleARN    string
	SrcProfile string
	Region     string
}

type kvStruct struct{ k, v string }

var (
	env     environments
	version = "dev"
	commit  = "none"
	date    = "unknown"
	req     = cloudwatchlogs.GetLogEventsInput{}
)

func init() {
	showVersion := false
	group := ""
	stream := ""
	flag.BoolVar(&showVersion, "version", false, "show version")
	flag.StringVar(&group, "g", "", "LogGroupName (is a required)")
	flag.StringVar(&stream, "s", "", "LogStreamName (is a required)")
	flag.Parse()
	if showVersion {
		fmt.Printf("%s version %v, commit %v, built at %v\n", filepath.Base(os.Args[0]), version, commit, date)
		os.Exit(0)
	}

	log.SetFlags(log.Lshortfile | log.LstdFlags)
	err := envconfig.Process("", &env)
	if err != nil {
		log.Fatal(err)
	}
	if len(env.Home) == 0 {
		env.Home, err = homedir.Dir()
		if err != nil {
			log.Fatal(err)
		}
	}
	if len(group) > 0 {
		env.LogGroup = group
	}
	if len(stream) > 0 {
		env.LogStream = stream
	}
	req.LogGroupName = &env.LogGroup
	req.LogStreamName = &env.LogStream
	//req.StartFromHead = aws.Bool(true)
	//req.EndTime = aws.Int64(0)
	//req.StartTime = aws.Int64(0)
	//req.Limit = aws.Int64(0)
}

func main() {
	var sess *session.Session
	sess = session.Must(session.NewSession())
	conf, err := getProfileConfig(getProfileEnv())
	if err == nil && len(conf.SrcProfile) > 0 {
		sess = getStsSession(conf)
	}
	c := cloudwatchlogs.New(sess)
	if err := getLogs(c, os.Stdout, req, env); err != nil {
		os.Exit(1)
	}
}

// see: https://github.com/boto/botocore/blob/2f0fa46380a59d606a70d76636d6d001772d8444/botocore/session.py#L82
func getProfileEnv() (profile string) {
	if env.AWSDefaultProfile != "" {
		return env.AWSDefaultProfile
	}
	profile = env.AWSProfile
	if len(profile) <= 0 {
		profile = "default"
	}
	return
}

func setEnvs(kvs []kvStruct) {
	for _, kv := range kvs {
		os.Setenv(kv.k, kv.v) // nolint errcheck
	}
}

func getStsSession(conf profileConfig) *session.Session {
	sess := session.Must(session.NewSession(&aws.Config{Credentials: credentials.NewSharedCredentials(awsFilePath(env.AWSSharedCredentialsFile, credPath, env.Home), conf.SrcProfile)}))
	return session.Must(session.NewSession(&aws.Config{Credentials: stscreds.NewCredentials(sess, conf.RoleARN), Region: &conf.Region}))
}

func awsFilePath(filePath, defaultPath, home string) string {
	if filePath != "" {
		if filePath[0] == '~' {
			return filepath.Join(home, filePath[1:])
		}
		return filePath
	}
	if home == "" {
		return ""
	}

	return filepath.Join(home, defaultPath)
}
func getProfileConfig(profile string) (res profileConfig, err error) {
	res, err = getProfile(profile, confPath)
	if err != nil {
		return res, err
	}
	if len(res.SrcProfile) > 0 && len(res.RoleARN) > 0 {
		return res, err
	}
	return getProfile(profile, credPath)
}

func getProfile(profile, configFileName string) (res profileConfig, err error) {
	cnfPath := awsFilePath(env.AWSConfigFile, configFileName, env.Home)
	config, err := ini.Load(cnfPath)
	if err != nil {
		return res, fmt.Errorf("failed to load shared credentials file. err:%s", err)
	}
	sec, err := config.GetSection(profile)
	if err != nil {
		// reference code -> https://github.com/aws/aws-sdk-go/blob/fae5afd566eae4a51e0ca0c38304af15618b8f57/aws/session/shared_config.go#L173-L181
		sec, err = config.GetSection(fmt.Sprintf("profile %s", profile))
		if err != nil {
			return res, fmt.Errorf("not found ini section err:%s", err)
		}
	}
	res.RoleARN = sec.Key(iniRoleARN).String()
	res.SrcProfile = sec.Key(iniSrcProfile).String()
	res.Region = sec.Key(iniRegion).String()
	// see: https://github.com/boto/botocore/blob/2f0fa46380a59d606a70d76636d6d001772d8444/botocore/session.py#L83
	if len(env.AWSDefaultRegion) > 0 {
		res.Region = env.AWSDefaultRegion
	}
	return res, nil
}

func getLogs(client cloudwatchlogsiface.CloudWatchLogsAPI, w io.Writer, input cloudwatchlogs.GetLogEventsInput, conf environments) error {
	res := &cloudwatchlogs.GetLogEventsOutput{}
	var err error
	for {
		if input.NextToken != nil && *res.NextForwardToken == *input.NextToken {
			return nil
		}
		input.NextToken = res.NextForwardToken
		res, err = client.GetLogEvents(&input)
		if err != nil {
			return err
		}
		for _, event := range res.Events {
			t := ""
			if conf.PrintTime {
				t = time.Unix(*event.Timestamp, 0).Format(time.RFC3339) + " "
			}
			if _, err := io.WriteString(w, t+*event.Message+"\n"); err != nil {
				return err
			}
		}
	}

}
