package main

import (
	"bytes"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/kms/kmsiface"
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
func TestGetTargetKVs(t *testing.T) {
	var vtests = []struct {
		envs     []string
		expected []kvStruct
	}{
		{
			[]string{"HOGE_PLAINTEXT=abcde", "FUGA_HOGE=hoge", "FUGA_PLAINTEXT=fugafuga"},
			[]kvStruct{{"HOGE_PLAINTEXT", "abcde"}, {"FUGA_PLAINTEXT", "fugafuga"}},
		},
	}
	for _, vt := range vtests {
		res := getTargetKVs(vt.envs, "_PLAINTEXT")
		for i := range vt.expected {
			if res[i] != vt.expected[i] {
				t.Errorf("getTargetKVs(%q), = %q, want %q", vt.envs[i], res, vt.expected[i])
			}
		}
	}
}

func TestEnvs(t *testing.T) {
	var vtests = []struct {
		kvs []kvStruct
	}{
		{
			[]kvStruct{{"aaa", "hoge"}, {"bbb", "hoge"}, {"ccc", "hoge"}},
		},
	}
	for _, vt := range vtests {
		setEnvs(vt.kvs)
		for _, expected := range vt.kvs {
			if os.Getenv(expected.k) != expected.v {
				t.Errorf("setEnvs(%q) = %q, want %q", vt.kvs, expected.k, expected.v)
			}
		}
	}
}
func TestEnvExportPrints(t *testing.T) {
	var vtests = []struct {
		kvs      []kvStruct
		expected string
	}{
		{
			[]kvStruct{{"aaa", "hoge"}, {"bbb", "hoge"}, {"ccc", "hoge"}},
			"export aaa=\"hoge\"\nexport bbb=\"hoge\"\nexport ccc=\"hoge\"\n",
		},
	}
	for _, vt := range vtests {
		var b bytes.Buffer
		envExportPrints(&b, vt.kvs)
		if b.String() != vt.expected {
			t.Errorf("kvs:%q, envExportPrint() = %q, want %q", vt.kvs, b.String(), vt.expected)
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
func TestGetExitCode(t *testing.T) {
	var vtests = []struct {
		cmd      []string
		expected int
	}{
		{[]string{"ls", "-abcefghijk"}, 2},
		{[]string{"ls", "-la"}, 0},
	}
	for _, vt := range vtests {
		cmd := exec.Command(vt.cmd[0], vt.cmd[1:]...) // nolint: gas
		res := getExitCode(cmd.Run())
		if res != vt.expected {
			t.Errorf("getExitCode(cmd:%q); = %q, want %q", vt.cmd, res, vt.expected)
		}
	}
}

/*
func TestGetProfile(t *testing.T) {
	var vtests = []struct {
		confFile string
		profile      string
		home string
		err *error
		configFileName string
		expected profileConfig
	}{

			confFile:         filepath.Join("~", awsCred),
			profile:          "testprof",
			home: testHomeA,
			configFileName: awsCred,
			expected:         filepath.Join(testHomeA, awsCred),
	}
	for _, vt := range vtests {
		env.Home = vt.home
		env.AWSConfigFile = vt.confFile
		r ,err:= getProfile(vt.profile, vt.configFileName)
		if r != vt.expected {
			t.Errorf("awsFilePath(%q, %q) = %q, want %q", vt.envValue, vt.defaultPathParam, r, vt.expected)
		}
	}
}
*/

type mockedKMS struct {
	kmsiface.KMSAPI
	resp kms.GenerateDataKeyOutput
}

func (m mockedKMS) GenerateDataKey(in *kms.GenerateDataKeyInput) (*kms.GenerateDataKeyOutput, error) {
	// Only need to return mocked response output
	res := m.resp
	res.Plaintext = make([]byte, len(m.resp.Plaintext))
	copy(res.Plaintext, m.resp.Plaintext)
	return &res, nil
}
func (m mockedKMS) Decrypt(in *kms.DecryptInput) (*kms.DecryptOutput, error) {
	// Only need to return mocked response output
	decResp := kms.DecryptOutput{KeyId: m.resp.KeyId, Plaintext: make([]byte, len(m.resp.Plaintext))}
	copy(decResp.Plaintext, m.resp.Plaintext)
	return &decResp, nil
}
func TestAesEncryptDecrypt(t *testing.T) {
	cases := []struct {
		resp kms.GenerateDataKeyOutput
		data string
	}{
		{
			resp: kms.GenerateDataKeyOutput{
				CiphertextBlob: []byte{
					0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0xcc, 0x53, 0xd5, 0xdb, 0x00, 0xdd, 0x87, 0x90,
					0x00, 0x00, 0x00, 0x00, 0x5d, 0x00, 0x00, 0x00, 0xa5, 0xc2, 0xfd, 0x6a, 0x00, 0xcc, 0x5b, 0x2c,
					0x00, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x30, 0xed, 0x11, 0x04, 0x00, 0x67, 0x59, 0x85,
					0x00, 0x00, 0x00, 0x00, 0x98, 0x00, 0x00, 0x00, 0x02, 0x3b, 0x01, 0x10, 0x00, 0x2a, 0xc0, 0xe4,
					0x00, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0xed, 0x2f, 0x0b, 0xe7, 0x00, 0x56, 0xa4, 0x04,
					0x00, 0x00, 0x00, 0x00, 0x86, 0x00, 0x00, 0x00, 0x6f, 0x01, 0x30, 0x6d, 0x00, 0x00, 0x30, 0x68,
					0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x01, 0x1e, 0x07, 0x01, 0x00, 0x06, 0x09, 0x60,
					0x00, 0x00, 0x00, 0x00, 0xfc, 0x00, 0x00, 0x00, 0xd0, 0xbf, 0xa9, 0xf3, 0x00, 0x63, 0x1e, 0x8c,
					0x00, 0x00, 0x00, 0x00, 0xfa, 0x00, 0x00, 0x00, 0x00, 0x06, 0x7e, 0x30, 0x00, 0x09, 0x2a, 0x86,
					0x00, 0x00, 0x00, 0x00, 0x8f, 0x00, 0x00, 0x00, 0x2b, 0x13, 0x5f, 0x87, 0x00, 0x02, 0x02, 0x0f,
					0x00, 0x00, 0x00, 0x00, 0xd0, 0x00, 0x00, 0x00, 0x94, 0x06, 0x89, 0x96, 0x00, 0xc5, 0x6e, 0xba,
					0x00, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00,
				}, // 184byte
				KeyId:     aws.String("arn:aws:kms:ap-northeast-1:00000000:key/1111111-1111-1111-111111111"),
				Plaintext: []byte("01234566890123456689012345668901"), // 32byte

			},
			data: "flkadjflksdjflaskfjlaskdjfaeiugywe98guasdgfjhasfdasfjasjdfoakjfdlkajdfoaiefhgiudhvuyasdtf7f3g48r723ighs65vr2749rujfosdhvaufh283rt8iufhjaosfjoHIOFHJDIFHE9fh93RHIUDHH7R651HGHDDHF",
		},
	}

	for i, c := range cases {
		mock := mockedKMS{resp: c.resp}
		res, err := aesEncrypt(&mock, *c.resp.KeyId, "keyname", c.data)
		log.Print(res)
		if err != nil {
			t.Fatalf("%d, unexpected error:%s", i, err)
		}
		//pp.Println(res, len(res))
		decrypt, err := aesDecrypt(&mock, "keyname", res)
		if err != nil {
			t.Fatalf("%d, unexpected error:%s", i, err)
		}
		if decrypt != c.data {
			t.Errorf("%d, decrypt:err  got %q, expected:%q", i, decrypt, c.data)
		}
	}
}

func TestEncryptEnvs(t *testing.T) {
	cases := []struct {
		envs []string
		resp kms.GenerateDataKeyOutput
		data string
	}{
		{
			resp: kms.GenerateDataKeyOutput{
				CiphertextBlob: []byte{
					0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0xcc, 0x53, 0xd5, 0xdb, 0x00, 0xdd, 0x87, 0x90,
					0x00, 0x00, 0x00, 0x00, 0x5d, 0x00, 0x00, 0x00, 0xa5, 0xc2, 0xfd, 0x6a, 0x00, 0xcc, 0x5b, 0x2c,
					0x00, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x30, 0xed, 0x11, 0x04, 0x00, 0x67, 0x59, 0x85,
					0x00, 0x00, 0x00, 0x00, 0x98, 0x00, 0x00, 0x00, 0x02, 0x3b, 0x01, 0x10, 0x00, 0x2a, 0xc0, 0xe4,
					0x00, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0xed, 0x2f, 0x0b, 0xe7, 0x00, 0x56, 0xa4, 0x04,
					0x00, 0x00, 0x00, 0x00, 0x86, 0x00, 0x00, 0x00, 0x6f, 0x01, 0x30, 0x6d, 0x00, 0x00, 0x30, 0x68,
					0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x01, 0x1e, 0x07, 0x01, 0x00, 0x06, 0x09, 0x60,
					0x00, 0x00, 0x00, 0x00, 0xfc, 0x00, 0x00, 0x00, 0xd0, 0xbf, 0xa9, 0xf3, 0x00, 0x63, 0x1e, 0x8c,
					0x00, 0x00, 0x00, 0x00, 0xfa, 0x00, 0x00, 0x00, 0x00, 0x06, 0x7e, 0x30, 0x00, 0x09, 0x2a, 0x86,
					0x00, 0x00, 0x00, 0x00, 0x8f, 0x00, 0x00, 0x00, 0x2b, 0x13, 0x5f, 0x87, 0x00, 0x02, 0x02, 0x0f,
					0x00, 0x00, 0x00, 0x00, 0xd0, 0x00, 0x00, 0x00, 0x94, 0x06, 0x89, 0x96, 0x00, 0xc5, 0x6e, 0xba,
					0x00, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00,
				}, // 184byte
				KeyId:     aws.String("arn:aws:kms:ap-northeast-1:00000000:key/1111111-1111-1111-111111111"),
				Plaintext: []byte("01234566890123456689012345668901"), // 32byte

			},
			data: "flkadjflksdjflaskfjlaskdjfaeiugywe98guasdgfjhasfdasfjasjdfoakjfdlkajdfoaiefhgiudhvuyasdtf7f3g48r723ighs65vr2749rujfosdhvaufh283rt8iufhjaosfjoHIOFHJDIFHE9fh93RHIUDHH7R651HGHDDHF",
			envs: []string{
				"HOGE_PLAINTEXT=fuga",
				//"AAAA_PLAINTEXT=foeojaodf",
				//"FUGA_PLAINTEXT=hogehogehfoahfoadfhdfaofd",
				"CCCC_PLAINTEXT=hogehogehf384fdhakdfdlsdklJFLDFJq28wefjfGIUEHFdjhf3u3ojffoahfoadfhdfaoffoahfoadfhdfaoffoahfoadfhdfaoffoahfoadfhdfaoffoahfoadfhdfaofoahfoadfhdfaofd",
			},
		},
	}

	for _, c := range cases {
		mock := mockedKMS{resp: c.resp}
		res, _ := encryptEnvs(&mock, *c.resp.KeyId, c.envs)
		encEnvs := make([]string, len(res))
		for j, kv := range res {
			encEnvs[j] = kv.k + "=" + kv.v
		}
		decRes, _ := decryptEnvs(&mock, encEnvs)
		for j, org := range c.envs {
			kvs := strings.SplitN(org, "=", 2)
			if decRes[j].v != kvs[1] {
				t.Errorf("%d, decrypt:err  got %q, expected:%q", j, decRes[j], kvs[1])
			}
		}
	}
}
func TestExecCommand(t *testing.T) {
	cases := []struct {
		args     []string
		expected int
	}{
		{
			args:     []string{"::::::::::"},
			expected: 1,
		},
		{
			args:     []string{"/bin/bash", "-c", ":"},
			expected: 0,
		},
	}
	for i, c := range cases {
		res := execCommand([]kvStruct{}, c.args)
		if res != c.expected {
			t.Errorf("%d, execCommand:err  got %q, expected:%q", i, res, c.expected)
		}
	}
}
