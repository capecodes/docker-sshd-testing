#!/bin/sh

mkdir -p keys/host
mkdir -p keys/user
mkdir -p ca

ssh-keygen -t rsa -b 4096 -m PEM -f ca/ca -C "CA" -N ""

ssh-keygen -t rsa-sha2-256 -b 4096 -m PEM -f ca/ca_rsa2_256 -C "CA" -N ""
ssh-keygen -t rsa-sha2-512 -b 4096 -m PEM -f ca/ca_rsa2_512 -C "CA" -N ""
ssh-keygen -t ed25519 -m PEM -f ca/ca_ed25519 -C "CA" -N ""
ssh-keygen -t ecdsa -b 256 -m PEM -f ca/ca_ecdsa_256 -C "CA" -N ""
ssh-keygen -t ecdsa -b 384 -m PEM -f ca/ca_ecdsa_384 -C "CA" -N ""
ssh-keygen -t ecdsa -b 521 -m PEM -f ca/ca_ecdsa_521 -C "CA" -N ""

ssh-keygen -t rsa -b 2048 -m PEM -f keys/host/host01 -C "host01" -N ""
ssh-keygen -t rsa -b 2048 -m PEM -f keys/host/host02 -C "host02" -N ""
ssh-keygen -t rsa -b 2048 -m PEM -f keys/host/host03 -C "host03" -N ""
ssh-keygen -t rsa -b 2048 -m PEM -f keys/host/host04 -C "host04" -N ""
ssh-keygen -t rsa -b 2048 -m PEM -f keys/host/host05 -C "host05" -N ""
ssh-keygen -t rsa -b 2048 -m PEM -f keys/host/host06 -C "host06" -N ""
ssh-keygen -t rsa -b 2048 -m PEM -f keys/host/host07 -C "host07" -N ""
ssh-keygen -t rsa -b 2048 -m PEM -f keys/host/host08 -C "host08" -N ""
ssh-keygen -t rsa -b 2048 -m PEM -f keys/host/host09 -C "host09" -N ""
ssh-keygen -t rsa -b 2048 -m PEM -f keys/host/host10 -C "host10" -N ""

ssh-keygen -t rsa-sha2-256 -b 2048 -m PEM -f keys/user/user01_rsa_sha2_256_2048 -C "user01" -N ""
ssh-keygen -t rsa-sha2-256 -b 2048 -m PEM -f keys/user/user02_rsa_sha2_256_2048 -C "user02" -N ""
ssh-keygen -t rsa-sha2-256 -b 2048 -m PEM -f keys/user/user03_rsa_sha2_256_2048 -C "user03" -N ""
ssh-keygen -t rsa-sha2-256 -b 2048 -m PEM -f keys/user/user04_rsa_sha2_256_2048 -C "user04" -N ""
ssh-keygen -t rsa-sha2-256 -b 2048 -m PEM -f keys/user/user05_rsa_sha2_256_2048 -C "user05" -N ""
ssh-keygen -t rsa-sha2-256 -b 2048 -m PEM -f keys/user/user06_rsa_sha2_256_2048 -C "user06" -N ""
ssh-keygen -t rsa-sha2-256 -b 2048 -m PEM -f keys/user/user07_rsa_sha2_256_2048 -C "user07" -N ""
ssh-keygen -t rsa-sha2-256 -b 2048 -m PEM -f keys/user/user08_rsa_sha2_256_2048 -C "user08" -N ""
ssh-keygen -t rsa-sha2-256 -b 2048 -m PEM -f keys/user/user09_rsa_sha2_256_2048 -C "user09" -N ""
ssh-keygen -t rsa-sha2-256 -b 2048 -m PEM -f keys/user/user10_rsa_sha2_256_2048 -C "user10" -N ""

ssh-keygen -t rsa-sha2-512 -b 2048 -m PEM -f keys/user/user01_rsa_sha2_512_2048 -C "user01" -N ""
ssh-keygen -t rsa-sha2-512 -b 2048 -m PEM -f keys/user/user02_rsa_sha2_512_2048 -C "user02" -N ""
ssh-keygen -t rsa-sha2-512 -b 2048 -m PEM -f keys/user/user03_rsa_sha2_512_2048 -C "user03" -N ""
ssh-keygen -t rsa-sha2-512 -b 2048 -m PEM -f keys/user/user04_rsa_sha2_512_2048 -C "user04" -N ""
ssh-keygen -t rsa-sha2-512 -b 2048 -m PEM -f keys/user/user05_rsa_sha2_512_2048 -C "user05" -N ""
ssh-keygen -t rsa-sha2-512 -b 2048 -m PEM -f keys/user/user06_rsa_sha2_512_2048 -C "user06" -N ""
ssh-keygen -t rsa-sha2-512 -b 2048 -m PEM -f keys/user/user07_rsa_sha2_512_2048 -C "user07" -N ""
ssh-keygen -t rsa-sha2-512 -b 2048 -m PEM -f keys/user/user08_rsa_sha2_512_2048 -C "user08" -N ""
ssh-keygen -t rsa-sha2-512 -b 2048 -m PEM -f keys/user/user09_rsa_sha2_512_2048 -C "user09" -N ""
ssh-keygen -t rsa-sha2-512 -b 2048 -m PEM -f keys/user/user10_rsa_sha2_512_2048 -C "user10" -N ""

ssh-keygen -t rsa-sha2-256 -b 4096 -m PEM -f keys/user/user01_rsa_sha2_256_4096 -C "user01" -N ""
ssh-keygen -t rsa-sha2-256 -b 4096 -m PEM -f keys/user/user02_rsa_sha2_256_4096 -C "user02" -N ""
ssh-keygen -t rsa-sha2-256 -b 4096 -m PEM -f keys/user/user03_rsa_sha2_256_4096 -C "user03" -N ""
ssh-keygen -t rsa-sha2-256 -b 4096 -m PEM -f keys/user/user04_rsa_sha2_256_4096 -C "user04" -N ""
ssh-keygen -t rsa-sha2-256 -b 4096 -m PEM -f keys/user/user05_rsa_sha2_256_4096 -C "user05" -N ""
ssh-keygen -t rsa-sha2-256 -b 4096 -m PEM -f keys/user/user06_rsa_sha2_256_4096 -C "user06" -N ""
ssh-keygen -t rsa-sha2-256 -b 4096 -m PEM -f keys/user/user07_rsa_sha2_256_4096 -C "user07" -N ""
ssh-keygen -t rsa-sha2-256 -b 4096 -m PEM -f keys/user/user08_rsa_sha2_256_4096 -C "user08" -N ""
ssh-keygen -t rsa-sha2-256 -b 4096 -m PEM -f keys/user/user09_rsa_sha2_256_4096 -C "user09" -N ""
ssh-keygen -t rsa-sha2-256 -b 4096 -m PEM -f keys/user/user10_rsa_sha2_256_4096 -C "user10" -N ""

ssh-keygen -t rsa-sha2-512 -b 4096 -m PEM -f keys/user/user01_rsa_sha2_512_4096 -C "user01" -N ""
ssh-keygen -t rsa-sha2-512 -b 4096 -m PEM -f keys/user/user02_rsa_sha2_512_4096 -C "user02" -N ""
ssh-keygen -t rsa-sha2-512 -b 4096 -m PEM -f keys/user/user03_rsa_sha2_512_4096 -C "user03" -N ""
ssh-keygen -t rsa-sha2-512 -b 4096 -m PEM -f keys/user/user04_rsa_sha2_512_4096 -C "user04" -N ""
ssh-keygen -t rsa-sha2-512 -b 4096 -m PEM -f keys/user/user05_rsa_sha2_512_4096 -C "user05" -N ""
ssh-keygen -t rsa-sha2-512 -b 4096 -m PEM -f keys/user/user06_rsa_sha2_512_4096 -C "user06" -N ""
ssh-keygen -t rsa-sha2-512 -b 4096 -m PEM -f keys/user/user07_rsa_sha2_512_4096 -C "user07" -N ""
ssh-keygen -t rsa-sha2-512 -b 4096 -m PEM -f keys/user/user08_rsa_sha2_512_4096 -C "user08" -N ""
ssh-keygen -t rsa-sha2-512 -b 4096 -m PEM -f keys/user/user09_rsa_sha2_512_4096 -C "user09" -N ""
ssh-keygen -t rsa-sha2-512 -b 4096 -m PEM -f keys/user/user10_rsa_sha2_512_4096 -C "user10" -N ""

ssh-keygen -t ed25519 -m PEM -f keys/user/user01_ed25519 -C "user01" -N ""
ssh-keygen -t ed25519 -m PEM -f keys/user/user02_ed25519 -C "user02" -N ""
ssh-keygen -t ed25519 -m PEM -f keys/user/user03_ed25519 -C "user03" -N ""
ssh-keygen -t ed25519 -m PEM -f keys/user/user04_ed25519 -C "user04" -N ""
ssh-keygen -t ed25519 -m PEM -f keys/user/user05_ed25519 -C "user05" -N ""
ssh-keygen -t ed25519 -m PEM -f keys/user/user06_ed25519 -C "user06" -N ""
ssh-keygen -t ed25519 -m PEM -f keys/user/user07_ed25519 -C "user07" -N ""
ssh-keygen -t ed25519 -m PEM -f keys/user/user08_ed25519 -C "user08" -N ""
ssh-keygen -t ed25519 -m PEM -f keys/user/user09_ed25519 -C "user09" -N ""
ssh-keygen -t ed25519 -m PEM -f keys/user/user10_ed25519 -C "user10" -N ""

ssh-keygen -t ecdsa -b 256 -m PEM -f keys/user/user01_ecdsa_256 -C "user01" -N ""
ssh-keygen -t ecdsa -b 256 -m PEM -f keys/user/user02_ecdsa_256 -C "user02" -N ""
ssh-keygen -t ecdsa -b 256 -m PEM -f keys/user/user03_ecdsa_256 -C "user03" -N ""
ssh-keygen -t ecdsa -b 256 -m PEM -f keys/user/user04_ecdsa_256 -C "user04" -N ""
ssh-keygen -t ecdsa -b 256 -m PEM -f keys/user/user05_ecdsa_256 -C "user05" -N ""
ssh-keygen -t ecdsa -b 256 -m PEM -f keys/user/user06_ecdsa_256 -C "user06" -N ""
ssh-keygen -t ecdsa -b 256 -m PEM -f keys/user/user07_ecdsa_256 -C "user07" -N ""
ssh-keygen -t ecdsa -b 256 -m PEM -f keys/user/user08_ecdsa_256 -C "user08" -N ""
ssh-keygen -t ecdsa -b 256 -m PEM -f keys/user/user09_ecdsa_256 -C "user09" -N ""
ssh-keygen -t ecdsa -b 256 -m PEM -f keys/user/user10_ecdsa_256 -C "user10" -N ""

ssh-keygen -t ecdsa -b 384 -m PEM -f keys/user/user01_ecdsa_384 -C "user01" -N ""
ssh-keygen -t ecdsa -b 384 -m PEM -f keys/user/user02_ecdsa_384 -C "user02" -N ""
ssh-keygen -t ecdsa -b 384 -m PEM -f keys/user/user03_ecdsa_384 -C "user03" -N ""
ssh-keygen -t ecdsa -b 384 -m PEM -f keys/user/user04_ecdsa_384 -C "user04" -N ""
ssh-keygen -t ecdsa -b 384 -m PEM -f keys/user/user05_ecdsa_384 -C "user05" -N ""
ssh-keygen -t ecdsa -b 384 -m PEM -f keys/user/user06_ecdsa_384 -C "user06" -N ""
ssh-keygen -t ecdsa -b 384 -m PEM -f keys/user/user07_ecdsa_384 -C "user07" -N ""
ssh-keygen -t ecdsa -b 384 -m PEM -f keys/user/user08_ecdsa_384 -C "user08" -N ""
ssh-keygen -t ecdsa -b 384 -m PEM -f keys/user/user09_ecdsa_384 -C "user09" -N ""
ssh-keygen -t ecdsa -b 384 -m PEM -f keys/user/user10_ecdsa_384 -C "user10" -N ""

ssh-keygen -t ecdsa -b 521 -m PEM -f keys/user/user01_ecdsa_521 -C "user01" -N ""
ssh-keygen -t ecdsa -b 521 -m PEM -f keys/user/user02_ecdsa_521 -C "user02" -N ""
ssh-keygen -t ecdsa -b 521 -m PEM -f keys/user/user03_ecdsa_521 -C "user03" -N ""
ssh-keygen -t ecdsa -b 521 -m PEM -f keys/user/user04_ecdsa_521 -C "user04" -N ""
ssh-keygen -t ecdsa -b 521 -m PEM -f keys/user/user05_ecdsa_521 -C "user05" -N ""
ssh-keygen -t ecdsa -b 521 -m PEM -f keys/user/user06_ecdsa_521 -C "user06" -N ""
ssh-keygen -t ecdsa -b 521 -m PEM -f keys/user/user07_ecdsa_521 -C "user07" -N ""
ssh-keygen -t ecdsa -b 521 -m PEM -f keys/user/user08_ecdsa_521 -C "user08" -N ""
ssh-keygen -t ecdsa -b 521 -m PEM -f keys/user/user09_ecdsa_521 -C "user09" -N ""
ssh-keygen -t ecdsa -b 521 -m PEM -f keys/user/user10_ecdsa_521 -C "user10" -N ""

ssh-keygen -t dsa -m PEM -f keys/user/user01_dsa -C "user01" -N ""
ssh-keygen -t dsa -m PEM -f keys/user/user02_dsa -C "user02" -N ""
ssh-keygen -t dsa -m PEM -f keys/user/user03_dsa -C "user03" -N ""
ssh-keygen -t dsa -m PEM -f keys/user/user04_dsa -C "user04" -N ""
ssh-keygen -t dsa -m PEM -f keys/user/user05_dsa -C "user05" -N ""
ssh-keygen -t dsa -m PEM -f keys/user/user06_dsa -C "user06" -N ""
ssh-keygen -t dsa -m PEM -f keys/user/user07_dsa -C "user07" -N ""
ssh-keygen -t dsa -m PEM -f keys/user/user08_dsa -C "user08" -N ""
ssh-keygen -t dsa -m PEM -f keys/user/user09_dsa -C "user09" -N ""
ssh-keygen -t dsa -m PEM -f keys/user/user10_dsa -C "user10" -N ""

ssh-keygen -s ./ca/ca -t rsa-sha2-256 -I user01 -n user01 ./keys/user/user01_rsa_sha2_256_2048
ssh-keygen -s ./ca/ca -t rsa-sha2-256 -I user02 -n user02 ./keys/user/user02_rsa_sha2_256_2048
ssh-keygen -s ./ca/ca -t rsa-sha2-256 -I user03 -n user03 ./keys/user/user03_rsa_sha2_256_2048
ssh-keygen -s ./ca/ca -t rsa-sha2-256 -I user04 -n user04 ./keys/user/user04_rsa_sha2_256_2048
ssh-keygen -s ./ca/ca -t rsa-sha2-256 -I user05 -n user05 ./keys/user/user05_rsa_sha2_256_2048
ssh-keygen -s ./ca/ca -t rsa-sha2-256 -I user06 -n user06 ./keys/user/user06_rsa_sha2_256_2048
ssh-keygen -s ./ca/ca -t rsa-sha2-256 -I user07 -n user07 ./keys/user/user07_rsa_sha2_256_2048
ssh-keygen -s ./ca/ca -t rsa-sha2-256 -I user08 -n user08 ./keys/user/user08_rsa_sha2_256_2048
ssh-keygen -s ./ca/ca -t rsa-sha2-256 -I user09 -n user09 ./keys/user/user09_rsa_sha2_256_2048
ssh-keygen -s ./ca/ca -t rsa-sha2-256 -I user10 -n user10 ./keys/user/user10_rsa_sha2_256_2048

ssh-keygen -s ./ca/ca -t rsa-sha2-512 -I user01 -n user01 ./keys/user/user01_rsa_sha2_512_2048
ssh-keygen -s ./ca/ca -t rsa-sha2-512 -I user02 -n user02 ./keys/user/user02_rsa_sha2_512_2048
ssh-keygen -s ./ca/ca -t rsa-sha2-512 -I user03 -n user03 ./keys/user/user03_rsa_sha2_512_2048
ssh-keygen -s ./ca/ca -t rsa-sha2-512 -I user04 -n user04 ./keys/user/user04_rsa_sha2_512_2048
ssh-keygen -s ./ca/ca -t rsa-sha2-512 -I user05 -n user05 ./keys/user/user05_rsa_sha2_512_2048
ssh-keygen -s ./ca/ca -t rsa-sha2-512 -I user06 -n user06 ./keys/user/user06_rsa_sha2_512_2048
ssh-keygen -s ./ca/ca -t rsa-sha2-512 -I user07 -n user07 ./keys/user/user07_rsa_sha2_512_2048
ssh-keygen -s ./ca/ca -t rsa-sha2-512 -I user08 -n user08 ./keys/user/user08_rsa_sha2_512_2048
ssh-keygen -s ./ca/ca -t rsa-sha2-512 -I user09 -n user09 ./keys/user/user09_rsa_sha2_512_2048
ssh-keygen -s ./ca/ca -t rsa-sha2-512 -I user10 -n user10 ./keys/user/user10_rsa_sha2_512_2048

ssh-keygen -s ./ca/ca -t rsa-sha2-256 -I user01 -n user01 ./keys/user/user01_rsa_sha2_256_4096
ssh-keygen -s ./ca/ca -t rsa-sha2-256 -I user02 -n user02 ./keys/user/user02_rsa_sha2_256_4096
ssh-keygen -s ./ca/ca -t rsa-sha2-256 -I user03 -n user03 ./keys/user/user03_rsa_sha2_256_4096
ssh-keygen -s ./ca/ca -t rsa-sha2-256 -I user04 -n user04 ./keys/user/user04_rsa_sha2_256_4096
ssh-keygen -s ./ca/ca -t rsa-sha2-256 -I user05 -n user05 ./keys/user/user05_rsa_sha2_256_4096
ssh-keygen -s ./ca/ca -t rsa-sha2-256 -I user06 -n user06 ./keys/user/user06_rsa_sha2_256_4096
ssh-keygen -s ./ca/ca -t rsa-sha2-256 -I user07 -n user07 ./keys/user/user07_rsa_sha2_256_4096
ssh-keygen -s ./ca/ca -t rsa-sha2-256 -I user08 -n user08 ./keys/user/user08_rsa_sha2_256_4096
ssh-keygen -s ./ca/ca -t rsa-sha2-256 -I user09 -n user09 ./keys/user/user09_rsa_sha2_256_4096
ssh-keygen -s ./ca/ca -t rsa-sha2-256 -I user10 -n user10 ./keys/user/user10_rsa_sha2_256_4096

ssh-keygen -s ./ca/ca -t rsa-sha2-512 -I user01 -n user01 ./keys/user/user01_rsa_sha2_512_4096
ssh-keygen -s ./ca/ca -t rsa-sha2-512 -I user02 -n user02 ./keys/user/user02_rsa_sha2_512_4096
ssh-keygen -s ./ca/ca -t rsa-sha2-512 -I user03 -n user03 ./keys/user/user03_rsa_sha2_512_4096
ssh-keygen -s ./ca/ca -t rsa-sha2-512 -I user04 -n user04 ./keys/user/user04_rsa_sha2_512_4096
ssh-keygen -s ./ca/ca -t rsa-sha2-512 -I user05 -n user05 ./keys/user/user05_rsa_sha2_512_4096
ssh-keygen -s ./ca/ca -t rsa-sha2-512 -I user06 -n user06 ./keys/user/user06_rsa_sha2_512_4096
ssh-keygen -s ./ca/ca -t rsa-sha2-512 -I user07 -n user07 ./keys/user/user07_rsa_sha2_512_4096
ssh-keygen -s ./ca/ca -t rsa-sha2-512 -I user08 -n user08 ./keys/user/user08_rsa_sha2_512_4096
ssh-keygen -s ./ca/ca -t rsa-sha2-512 -I user09 -n user09 ./keys/user/user09_rsa_sha2_512_4096
ssh-keygen -s ./ca/ca -t rsa-sha2-512 -I user10 -n user10 ./keys/user/user10_rsa_sha2_512_4096

ssh-keygen -s ./ca/ca -I user01 -n user01 ./keys/user/user01_ed25519
ssh-keygen -s ./ca/ca -I user02 -n user02 ./keys/user/user02_ed25519
ssh-keygen -s ./ca/ca -I user03 -n user03 ./keys/user/user03_ed25519
ssh-keygen -s ./ca/ca -I user04 -n user04 ./keys/user/user04_ed25519
ssh-keygen -s ./ca/ca -I user05 -n user05 ./keys/user/user05_ed25519
ssh-keygen -s ./ca/ca -I user06 -n user06 ./keys/user/user06_ed25519
ssh-keygen -s ./ca/ca -I user07 -n user07 ./keys/user/user07_ed25519
ssh-keygen -s ./ca/ca -I user08 -n user08 ./keys/user/user08_ed25519
ssh-keygen -s ./ca/ca -I user09 -n user09 ./keys/user/user09_ed25519
ssh-keygen -s ./ca/ca -I user10 -n user10 ./keys/user/user10_ed25519

ssh-keygen -s ./ca/ca -I user01 -n user01 ./keys/user/user01_ecdsa_256
ssh-keygen -s ./ca/ca -I user02 -n user02 ./keys/user/user02_ecdsa_256
ssh-keygen -s ./ca/ca -I user03 -n user03 ./keys/user/user03_ecdsa_256
ssh-keygen -s ./ca/ca -I user04 -n user04 ./keys/user/user04_ecdsa_256
ssh-keygen -s ./ca/ca -I user05 -n user05 ./keys/user/user05_ecdsa_256
ssh-keygen -s ./ca/ca -I user06 -n user06 ./keys/user/user06_ecdsa_256
ssh-keygen -s ./ca/ca -I user07 -n user07 ./keys/user/user07_ecdsa_256
ssh-keygen -s ./ca/ca -I user08 -n user08 ./keys/user/user08_ecdsa_256
ssh-keygen -s ./ca/ca -I user09 -n user09 ./keys/user/user09_ecdsa_256
ssh-keygen -s ./ca/ca -I user10 -n user10 ./keys/user/user10_ecdsa_256

ssh-keygen -s ./ca/ca -I user01 -n user01 ./keys/user/user01_ecdsa_384
ssh-keygen -s ./ca/ca -I user02 -n user02 ./keys/user/user02_ecdsa_384
ssh-keygen -s ./ca/ca -I user03 -n user03 ./keys/user/user03_ecdsa_384
ssh-keygen -s ./ca/ca -I user04 -n user04 ./keys/user/user04_ecdsa_384
ssh-keygen -s ./ca/ca -I user05 -n user05 ./keys/user/user05_ecdsa_384
ssh-keygen -s ./ca/ca -I user06 -n user06 ./keys/user/user06_ecdsa_384
ssh-keygen -s ./ca/ca -I user07 -n user07 ./keys/user/user07_ecdsa_384
ssh-keygen -s ./ca/ca -I user08 -n user08 ./keys/user/user08_ecdsa_384
ssh-keygen -s ./ca/ca -I user09 -n user09 ./keys/user/user09_ecdsa_384
ssh-keygen -s ./ca/ca -I user10 -n user10 ./keys/user/user10_ecdsa_384

ssh-keygen -s ./ca/ca -I user01 -n user01 ./keys/user/user01_ecdsa_521
ssh-keygen -s ./ca/ca -I user02 -n user02 ./keys/user/user02_ecdsa_521
ssh-keygen -s ./ca/ca -I user03 -n user03 ./keys/user/user03_ecdsa_521
ssh-keygen -s ./ca/ca -I user04 -n user04 ./keys/user/user04_ecdsa_521
ssh-keygen -s ./ca/ca -I user05 -n user05 ./keys/user/user05_ecdsa_521
ssh-keygen -s ./ca/ca -I user06 -n user06 ./keys/user/user06_ecdsa_521
ssh-keygen -s ./ca/ca -I user07 -n user07 ./keys/user/user07_ecdsa_521
ssh-keygen -s ./ca/ca -I user08 -n user08 ./keys/user/user08_ecdsa_521
ssh-keygen -s ./ca/ca -I user09 -n user09 ./keys/user/user09_ecdsa_521
ssh-keygen -s ./ca/ca -I user10 -n user10 ./keys/user/user10_ecdsa_521

ssh-keygen -s ./ca/ca -I user01 -n user01 ./keys/user/user01_dsa
ssh-keygen -s ./ca/ca -I user02 -n user02 ./keys/user/user02_dsa
ssh-keygen -s ./ca/ca -I user03 -n user03 ./keys/user/user03_dsa
ssh-keygen -s ./ca/ca -I user04 -n user04 ./keys/user/user04_dsa
ssh-keygen -s ./ca/ca -I user05 -n user05 ./keys/user/user05_dsa
ssh-keygen -s ./ca/ca -I user06 -n user06 ./keys/user/user06_dsa
ssh-keygen -s ./ca/ca -I user07 -n user07 ./keys/user/user07_dsa
ssh-keygen -s ./ca/ca -I user08 -n user08 ./keys/user/user08_dsa
ssh-keygen -s ./ca/ca -I user09 -n user09 ./keys/user/user09_dsa
ssh-keygen -s ./ca/ca -I user10 -n user10 ./keys/user/user10_dsa

cat ./keys/user/user01_rsa_sha2_256_2048.pub ./keys/user/user01_rsa_sha2_512_2048.pub ./keys/user/user01_rsa_sha2_256_4096.pub ./keys/user/user01_rsa_sha2_512_4096.pub ./keys/user/user01_ed25519.pub ./keys/user/user01_ecdsa_256.pub ./keys/user/user01_ecdsa_384.pub ./keys/user/user01_ecdsa_521.pub ./keys/user/user01_dsa.pub > ./keys/user/user01_authorized_keys
cat ./keys/user/user02_rsa_sha2_256_2048.pub ./keys/user/user02_rsa_sha2_512_2048.pub ./keys/user/user02_rsa_sha2_256_4096.pub ./keys/user/user02_rsa_sha2_512_4096.pub ./keys/user/user02_ed25519.pub ./keys/user/user02_ecdsa_256.pub ./keys/user/user02_ecdsa_384.pub ./keys/user/user02_ecdsa_521.pub ./keys/user/user02_dsa.pub > ./keys/user/user02_authorized_keys
cat ./keys/user/user03_rsa_sha2_256_2048.pub ./keys/user/user03_rsa_sha2_512_2048.pub ./keys/user/user03_rsa_sha2_256_4096.pub ./keys/user/user03_rsa_sha2_512_4096.pub ./keys/user/user03_ed25519.pub ./keys/user/user03_ecdsa_256.pub ./keys/user/user03_ecdsa_384.pub ./keys/user/user03_ecdsa_521.pub ./keys/user/user03_dsa.pub > ./keys/user/user03_authorized_keys
cat ./keys/user/user04_rsa_sha2_256_2048.pub ./keys/user/user04_rsa_sha2_512_2048.pub ./keys/user/user04_rsa_sha2_256_4096.pub ./keys/user/user04_rsa_sha2_512_4096.pub ./keys/user/user04_ed25519.pub ./keys/user/user04_ecdsa_256.pub ./keys/user/user04_ecdsa_384.pub ./keys/user/user04_ecdsa_521.pub ./keys/user/user04_dsa.pub > ./keys/user/user04_authorized_keys
cat ./keys/user/user05_rsa_sha2_256_2048.pub ./keys/user/user05_rsa_sha2_512_2048.pub ./keys/user/user05_rsa_sha2_256_4096.pub ./keys/user/user05_rsa_sha2_512_4096.pub ./keys/user/user05_ed25519.pub ./keys/user/user05_ecdsa_256.pub ./keys/user/user05_ecdsa_384.pub ./keys/user/user05_ecdsa_521.pub ./keys/user/user05_dsa.pub > ./keys/user/user05_authorized_keys
cat ./keys/user/user06_rsa_sha2_256_2048.pub ./keys/user/user06_rsa_sha2_512_2048.pub ./keys/user/user06_rsa_sha2_256_4096.pub ./keys/user/user06_rsa_sha2_512_4096.pub ./keys/user/user06_ed25519.pub ./keys/user/user06_ecdsa_256.pub ./keys/user/user06_ecdsa_384.pub ./keys/user/user06_ecdsa_521.pub ./keys/user/user06_dsa.pub > ./keys/user/user06_authorized_keys
cat ./keys/user/user07_rsa_sha2_256_2048.pub ./keys/user/user07_rsa_sha2_512_2048.pub ./keys/user/user07_rsa_sha2_256_4096.pub ./keys/user/user07_rsa_sha2_512_4096.pub ./keys/user/user07_ed25519.pub ./keys/user/user07_ecdsa_256.pub ./keys/user/user07_ecdsa_384.pub ./keys/user/user07_ecdsa_521.pub ./keys/user/user07_dsa.pub > ./keys/user/user07_authorized_keys
cat ./keys/user/user08_rsa_sha2_256_2048.pub ./keys/user/user08_rsa_sha2_512_2048.pub ./keys/user/user08_rsa_sha2_256_4096.pub ./keys/user/user08_rsa_sha2_512_4096.pub ./keys/user/user08_ed25519.pub ./keys/user/user08_ecdsa_256.pub ./keys/user/user08_ecdsa_384.pub ./keys/user/user08_ecdsa_521.pub ./keys/user/user08_dsa.pub > ./keys/user/user08_authorized_keys
cat ./keys/user/user09_rsa_sha2_256_2048.pub ./keys/user/user09_rsa_sha2_512_2048.pub ./keys/user/user09_rsa_sha2_256_4096.pub ./keys/user/user09_rsa_sha2_512_4096.pub ./keys/user/user09_ed25519.pub ./keys/user/user09_ecdsa_256.pub ./keys/user/user09_ecdsa_384.pub ./keys/user/user09_ecdsa_521.pub ./keys/user/user09_dsa.pub > ./keys/user/user09_authorized_keys
cat ./keys/user/user10_rsa_sha2_256_2048.pub ./keys/user/user10_rsa_sha2_512_2048.pub ./keys/user/user10_rsa_sha2_256_4096.pub ./keys/user/user10_rsa_sha2_512_4096.pub ./keys/user/user10_ed25519.pub ./keys/user/user10_ecdsa_256.pub ./keys/user/user10_ecdsa_384.pub ./keys/user/user10_ecdsa_521.pub ./keys/user/user10_dsa.pub > ./keys/user/user10_authorized_keys
