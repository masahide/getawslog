package main

import (
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/gob"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/kms/kmsiface"
	"github.com/go-ini/ini"
	"github.com/kelseyhightower/envconfig"
	"github.com/mitchellh/go-homedir"
	"github.com/pkg/errors"
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
	KmsCmk                   string `envconfig:"KMS_CMK"`
	Home                     string `envconfig:"HOME"`
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
)

func init() {
	showVersion := false
	flag.BoolVar(&showVersion, "version", false, "show version")
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
}

func main() {
	sess := session.Must(session.NewSession())
	conf, err := getProfileConfig(getProfileEnv())
	if err == nil && len(conf.SrcProfile) > 0 {
		sess = getStsSession(conf)
	}
	kmsSvc := kms.New(sess)
	var envs []kvStruct
	switch {
	case len(env.KmsCmk) > 0:
		envs, err = encryptEnvs(kmsSvc, env.KmsCmk, os.Environ())
	default:
		envs, err = decryptEnvs(kmsSvc, os.Environ())
	}
	if err != nil {
		log.Print(err)
	}
	args := flag.Args()
	if len(args) <= 0 {
		envExportPrints(os.Stdout, envs)
		return
	}
	os.Exit(execCommand(envs, args))
}

func execCommand(plainKVs []kvStruct, args []string) int {
	setEnvs(plainKVs)
	cmd := exec.Command(args[0], args[1:]...) // nolint: gas
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return getExitCode(cmd.Run())
}

func getTargetKVs(allenvs []string, suffix string) []kvStruct {
	envs := make([]kvStruct, 0, len(allenvs))
	for _, kv := range allenvs {
		values := strings.SplitN(kv, "=", 2)
		if len(values) >= 2 {
			env := kvStruct{values[0], values[1]}
			if strings.HasSuffix(env.k, suffix) {
				envs = append(envs, env)
			}
		}
	}
	return envs

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

func envExportPrints(out io.Writer, kvs []kvStruct) {
	for _, kv := range kvs {
		if len(kv.k) > 0 {
			fmt.Fprintf(out, "export %s=\"%s\"\n", kv.k, kv.v) // nolint errcheck
		}
	}
}

func getExitCode(err error) int {
	if err == nil {
		return 0
	}
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		log.Print(err)
		return 1
	}
	s, ok := exitErr.Sys().(syscall.WaitStatus)
	if !ok {
		log.Print(err)
		return 2
	}
	return s.ExitStatus()
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
	return res, nil
}

type data struct {
	Encrypted  []byte
	CryptedKey []byte
}

func aesEncrypt(kmsSvc kmsiface.KMSAPI, keyID, keyName, plaintext string) (string, error) {
	res, err := kmsSvc.GenerateDataKey(&kms.GenerateDataKeyInput{
		KeyId:             aws.String(keyID),
		KeySpec:           aws.String("AES_256"),
		EncryptionContext: map[string]*string{"keyName": &keyName},
	})
	if err != nil {
		return "", errors.Wrap(err, "kms.GenerateDataKey failed")
	}
	defer clearKey(res.Plaintext)

	block, err := aes.NewCipher(res.Plaintext)
	if err != nil {
		return "", errors.Wrap(err, "aes.NewCipher failed")
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", errors.Wrap(err, "cipher.NewGCM failed")
	}
	nonce := make([]byte, aesgcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", errors.Wrap(err, "ReadFull(rend.Reader,nonce) failed")
	}
	buf := &bytes.Buffer{}
	base64w := base64.NewEncoder(base64.StdEncoding, buf)
	zwriter, err := zlib.NewWriterLevel(base64w, zlib.BestCompression)
	if err != nil {
		return "", errors.Wrap(err, "zlib.NewWriterLevel failed")
	}
	err = gob.NewEncoder(zwriter).Encode(
		data{
			CryptedKey: res.CiphertextBlob,
			Encrypted:  aesgcm.Seal(nonce, nonce, []byte(plaintext), []byte(keyID)),
		},
	)
	zwriter.Close() // nolint errcheck
	base64w.Close() // nolint errcheck
	if err != nil {
		return "", errors.Wrap(err, "gob. encode failed")
	}
	return buf.String(), nil
}

func aesDecrypt(kmsSvc kmsiface.KMSAPI, keyName, encoded string) (string, error) {
	zReader, err := zlib.NewReader(
		base64.NewDecoder(base64.StdEncoding,
			strings.NewReader(encoded),
		),
	)
	if err != nil {
		return "", errors.Wrap(err, "zlib.NewReader failed")
	}
	defer zReader.Close() // nolint errcheck
	cryptData := data{}
	if err = gob.NewDecoder(zReader).Decode(&cryptData); err != nil {
		return "", errors.Wrap(err, "gob decode failed")
	}

	input := &kms.DecryptInput{
		CiphertextBlob:    cryptData.CryptedKey,
		EncryptionContext: map[string]*string{"keyName": &keyName},
	}
	result, err := kmsSvc.Decrypt(input)
	if err != nil {
		return "", errors.Errorf("kms Decrypt failed. KEY:%s Dcrypt err:%s", keyName, err)
	}
	defer clearKey(result.Plaintext)
	block, err := aes.NewCipher(result.Plaintext)
	if err != nil {
		return "", errors.Wrap(err, "aes NewCipher failed")
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", errors.Wrap(err, "cipher.NewGCM failed")
	}
	nonce, ciphertext := cryptData.Encrypted[:aesgcm.NonceSize()], cryptData.Encrypted[aesgcm.NonceSize():]
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, []byte(*result.KeyId))
	if err != nil {
		return "", errors.Wrap(err, "aesgcm.Open failed")
	}
	return string(plaintext), nil
}

func encryptEnvs(kmsSvc kmsiface.KMSAPI, keyID string, envs []string) ([]kvStruct, error) {
	kvs := getTargetKVs(envs, "_PLAINTEXT")
	for i, env := range kvs {
		key := strings.TrimSuffix(env.k, "_PLAINTEXT")
		encrypted, err := aesEncrypt(kmsSvc, keyID, key, env.v)
		if err != nil {
			log.Fatal(err)
		}
		kvs[i].k = key + "_KMS"
		kvs[i].v = encrypted
	}
	return kvs, nil
}

func decryptEnvs(kmsSvc kmsiface.KMSAPI, envs []string) ([]kvStruct, error) {
	kvs := getTargetKVs(envs, "_KMS")
	res := make([]kvStruct, len(envs))
	for i, env := range kvs {
		key := strings.TrimSuffix(env.k, "_KMS")
		plantext, err := aesDecrypt(kmsSvc, key, env.v)
		if err != nil {
			return res, err
		}
		res[i].k = key
		res[i].v = plantext
	}
	return res, nil
}

func clearKey(data []byte) {
	for i := range data {
		data[i] = 0
	}
}
