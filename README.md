# Overview

A simple testing OpenSSH based sshd server

Comes with

* 10 non-root users that all have password and key based authentication available
* 10 host keypairs to choose from

# Running

Requires setting an env var `SSH_HOST_KEY` to a absolute path of one of the 10 host keypairs

```bash
docker run -d --name=sshd-server -e SSH_HOST_KEY=/keys/host/host01 -p 2222:22  capecodes/sshd-testing:latest
```
# Host Keypairs

1. `/keys/host/host01`
1. `/keys/host/host02`
1. `/keys/host/host03`
1. `/keys/host/host04`
1. `/keys/host/host05`
1. `/keys/host/host06`
1. `/keys/host/host07`
1. `/keys/host/host08`
1. `/keys/host/host09`
1. `/keys/host/host10`

## Users

|username|password|homedir|
|--------|--------|-------|
|`user01`|`password01`|`/home/user01`|
|`user02`|`password02`|`/home/user02`|
|`user03`|`password03`|`/home/user03`|
|`user04`|`password04`|`/home/user04`|
|`user05`|`password05`|`/home/user05`|
|`user06`|`password06`|`/home/user06`|
|`user07`|`password07`|`/home/user07`|
|`user08`|`password08`|`/home/user08`|
|`user09`|`password09`|`/home/user09`|
|`user10`|`password10`|`/home/user10`|

The user keypairs are found in this repositories `keys/user` directory

## User Certificates

ssh -vvv -i ./keys/user/user01_rsa_sha2_256_2048 -oCertificateFile=./keys/user/user01_rsa_sha2_256_2048-cert.pub -oPort=2222 user01@localhost
ssh -vvv -i ./keys/user/user01_rsa_sha2_512_2048 -oCertificateFile=./keys/user/user01_rsa_sha2_512_2048-cert.pub -oPort=2222 user01@localhost
ssh -vvv -i ./keys/user/user01_rsa_sha2_256_4096 -oCertificateFile=./keys/user/user01_rsa_sha2_256_4096-cert.pub -oPort=2222 user01@localhost
ssh -vvv -i ./keys/user/user01_rsa_sha2_512_4096 -oCertificateFile=./keys/user/user01_rsa_sha2_512_4096-cert.pub -oPort=2222 user01@localhost
ssh -vvv -i ./keys/user/user01_ed25519 -oCertificateFile=./keys/user/user01_ed25519-cert.pub -oPort=2222 user01@localhost
ssh -vvv -i ./keys/user/user01_ecdsa_256 -oCertificateFile=./keys/user/user01_ecdsa_256-cert.pub -oPort=2222 user01@localhost
ssh -vvv -i ./keys/user/user01_ecdsa_384 -oCertificateFile=./keys/user/user01_ecdsa_384-cert.pub -oPort=2222 user01@localhost
ssh -vvv -i ./keys/user/user01_ecdsa_521 -oCertificateFile=./keys/user/user01_ecdsa_521-cert.pub -oPort=2222 user01@localhost

ssh -v -i ./keys/user/user01_dsa -oCertificateFile=./keys/user/user01_dsa-cert.pub -oPort=2222 user01@localhost




ssh -v -oCertificateFile=./user01_rsa_4096-cert.pub -oPort=2222 user01@localhost

sig algs: 

rsa:
  rsa-sha-512 (preferred)
  rsa-sha-256

ed25519:
  ssh-ed25519

ecdsa:
  ecdsa-sha2-nistp256
  ecdsa-sha2-nistp384
  ecdsa-sha2-nistp521