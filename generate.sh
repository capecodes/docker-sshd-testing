#!/bin/sh

mkdir -p keys/host
mkdir -p keys/user

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

ssh-keygen -t rsa -b 2048 -m PEM -f keys/user/user01 -C "user01" -N ""
ssh-keygen -t rsa -b 2048 -m PEM -f keys/user/user02 -C "user02" -N ""
ssh-keygen -t rsa -b 2048 -m PEM -f keys/user/user03 -C "user03" -N ""
ssh-keygen -t rsa -b 2048 -m PEM -f keys/user/user04 -C "user04" -N ""
ssh-keygen -t rsa -b 2048 -m PEM -f keys/user/user05 -C "user05" -N ""
ssh-keygen -t rsa -b 2048 -m PEM -f keys/user/user06 -C "user06" -N ""
ssh-keygen -t rsa -b 2048 -m PEM -f keys/user/user07 -C "user07" -N ""
ssh-keygen -t rsa -b 2048 -m PEM -f keys/user/user08 -C "user08" -N ""
ssh-keygen -t rsa -b 2048 -m PEM -f keys/user/user09 -C "user09" -N ""
ssh-keygen -t rsa -b 2048 -m PEM -f keys/user/user10 -C "user10" -N ""
