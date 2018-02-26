package main

import (
	"bytes"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs/cloudwatchlogsiface"
)

const (
	testHomeA = "./test/a"
	testHomeB = "./test/b"
	awsCred   = ".aws/credentials"
	awsConf   = ".aws/config"
)

func TestGetProfileEnv(t *testing.T) {
	var vtests = []struct {
		defValue  string
		profValue string
		expected  string
	}{
		{"def", "prof", "def"},
		{"", "prof", "prof"},
	}
	for _, vt := range vtests {
		env.AWSDefaultProfile = vt.defValue
		env.AWSProfile = vt.profValue
		r := getProfileEnv()
		if r != vt.expected {
			t.Errorf("AWSDefaultProfile=%q,AWSProfile=%q,getProfileEnv() = %q, want %q", vt.defValue, vt.profValue, r, vt.expected)
		}
	}
}

func TestAwsFilePath(t *testing.T) {
	var vtests = []struct {
		envValue         string
		defaultPathParam string
		expected         string
	}{
		{
			envValue:         filepath.Join("~", awsCred),
			defaultPathParam: awsCred,
			expected:         filepath.Join(testHomeA, awsCred),
		}, {
			envValue:         filepath.Join("~", awsConf),
			defaultPathParam: awsConf,
			expected:         filepath.Join(testHomeA, awsConf),
		}, {
			envValue:         "",
			defaultPathParam: ".aws/credentials",
			expected:         filepath.Join(testHomeA, awsCred),
		}, {
			envValue:         "",
			defaultPathParam: awsConf,
			expected:         filepath.Join(testHomeA, awsConf),
		},
	}

	env.Home = testHomeA
	for _, vt := range vtests {
		r := awsFilePath(vt.envValue, vt.defaultPathParam, testHomeA)
		if r != vt.expected {
			t.Errorf("awsFilePath(%q, %q) = %q, want %q", vt.envValue, vt.defaultPathParam, r, vt.expected)
		}
	}
}

func TestGetProfileConfig(t *testing.T) {
	var vtests = []struct {
		home     string
		profile  string
		err      *string
		expected profileConfig
	}{
		{
			testHomeA,
			"testprof",
			nil,
			profileConfig{
				RoleARN:    "arn:aws:iam::123456789012:role/Admin",
				Region:     "ap-northeast-1",
				SrcProfile: "srcprof",
				//SrcRegion:    "us-east-1",
				//SrcAccountID: "000000000000",
			},
		},
		{
			testHomeB,
			"not_profile_prefix",
			nil,
			profileConfig{
				RoleARN:    "arn:aws:iam::123456789011:role/a",
				Region:     "ap-northeast-1",
				SrcProfile: "srcprof",
				//SrcRegion:    "us-east-1",
				//SrcAccountID: "000000000000",
			},
		},
		{
			testHomeB,
			"src_default",
			nil,
			profileConfig{
				RoleARN:    "arn:aws:iam::123456789011:role/b",
				Region:     "ap-northeast-1",
				SrcProfile: "default",
				//SrcRegion:    "us-east-1",
				//SrcAccountID: "000000000000",
			},
		},
		{
			testHomeB,
			"none",
			aws.String("not found ini section err:section 'profile none' does not exist"),
			profileConfig{
				RoleARN:    "",
				Region:     "",
				SrcProfile: "",
				//SrcRegion:    "us-east-1",
				//SrcAccountID: "000000000000",
			},
		},
	}
	for _, vt := range vtests {
		env.Home = vt.home
		res, err := getProfileConfig(vt.profile)
		if err != nil && vt.err == nil {
			t.Errorf("err getProfileConfig(%q) = err:%s", vt.profile, err)
		}
		if err != nil {
			if err.Error() != *vt.err {
				t.Errorf("err getProfileConfig(%q) = err:%s", vt.profile, err)
			}
		}
		if res != vt.expected {
			t.Errorf("getProfileConfig(%q); = %q, want %q", vt.profile, res, vt.expected)
		}
	}
}

type mockedCWL struct {
	cloudwatchlogsiface.CloudWatchLogsAPI
	resp cloudwatchlogs.GetLogEventsOutput
	err  error
}

func (m mockedCWL) GetLogEvents(in *cloudwatchlogs.GetLogEventsInput) (*cloudwatchlogs.GetLogEventsOutput, error) {
	// Only need to return mocked response output
	if in.NextToken != nil {
		m.resp.Events = []*cloudwatchlogs.OutputLogEvent{}
	}
	if m.err != nil {
		return nil, m.err
	}
	return &m.resp, nil
}

func TestGetLogs(t *testing.T) {
	var vtests = []struct {
		input cloudwatchlogs.GetLogEventsInput
		conf  environments
		resp  cloudwatchlogs.GetLogEventsOutput
		err   error
	}{
		{
			cloudwatchlogs.GetLogEventsInput{
				LogGroupName:  aws.String(""),
				LogStreamName: aws.String(""),
			},
			environments{PrintTime: true},
			cloudwatchlogs.GetLogEventsOutput{
				Events: []*cloudwatchlogs.OutputLogEvent{
					&cloudwatchlogs.OutputLogEvent{
						Timestamp: aws.Int64(1519556892),
						Message:   aws.String("sample message log........"),
					},
					&cloudwatchlogs.OutputLogEvent{
						Timestamp: aws.Int64(1519556893),
						Message:   aws.String("sample message log2........"),
					},
				},
				NextForwardToken: aws.String("hogehoge"),
			},
			nil,
		},
		{
			cloudwatchlogs.GetLogEventsInput{},
			environments{},
			cloudwatchlogs.GetLogEventsOutput{},
			errors.New("test error"),
		},
	}
	for i, vt := range vtests {
		var b bytes.Buffer
		m := mockedCWL{
			resp: vt.resp,
			err:  vt.err,
		}
		err := getLogs(&m, &b, vt.input, vt.conf)
		if err != vt.err {
			t.Errorf("err %d:getLogs() = err:%s, want:%s", i, err, vt.err)
		}
		lines := strings.Split(b.String(), "\n")
		for j, line := range lines {
			if len(line) == 0 {
				break
			}
			s := strings.SplitN(line, " ", 2)
			mes := line
			if j > len(vt.resp.Events) {
				t.Errorf("err len(split(line, ' '))%d > len(vt.resp.Events)%d s=%s", j, len(vt.resp.Events), s)
			}
			if vt.conf.PrintTime {
				_, err := time.Parse(time.RFC3339, s[0])
				if err != nil {
					t.Errorf("err %d:getLogs() = %s, PrintTime:%v", i, line, vt.conf.PrintTime)
				}
				mes = s[1]
			}
			if mes != *vt.resp.Events[j].Message {
				t.Errorf("err %d:getLogs() = %s, want:%s", i, mes, *vt.resp.Events[j].Message)
			}

		}
	}

}
