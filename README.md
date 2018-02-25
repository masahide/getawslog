# getawslog

Command wrapper for encryption and decryption using aws kms.

[![Go Report Card](https://goreportcard.com/badge/github.com/masahide/getawslog)](https://goreportcard.com/report/github.com/masahide/getawslog)
[![Build Status](https://travis-ci.org/masahide/getawslog.svg?branch=master)](https://travis-ci.org/masahide/getawslog)
[![codecov](https://codecov.io/gh/masahide/getawslog/branch/master/graph/badge.svg)](https://codecov.io/gh/masahide/getawslog)
[![goreleaser](https://img.shields.io/badge/powered%20by-goreleaser-green.svg?style=flat-square)](https://github.com/goreleaser)

## Description

getawslog is use aws kms to encrypt and decrypt it and set it to environment variable.

## Installation

### Linux

For RHEL/CentOS:

```bash
sudo yum install https://github.com/masahide/getawslog/releases/download/v0.1.0/getawslog_amd64.rpm
```

For Ubuntu/Debian:

```bash
wget -qO /tmp/getawslog_amd64.deb https://github.com/masahide/getawslog/releases/download/v0.1.0/getawslog_amd64.deb && sudo dpkg -i /tmp/getawslog_amd64.deb
```

### macOS


install via [brew](https://brew.sh):

```bash
brew tap masahide/getawslog https://github.com/masahide/getawslog
brew install getawslog
```


## Usage


