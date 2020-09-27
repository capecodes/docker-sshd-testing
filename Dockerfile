# (C) 2017, Cape Codes, <info@cape.codes>
# Dual licensed with MIT and GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

FROM alpine:3.12

MAINTAINER Cape Codes <info@cape.codes>

RUN apk --update add supervisor openssh openssh-server bash \
  && rm -rf /var/cache/apk/* \
# sshd requires a "privilege separation directory"
  && mkdir /var/run/sshd \
# add a group for all the ssh users
  && addgroup sftpusers \
# add a non-root local users
  && adduser -D user01 -G sftpusers \
  && adduser -D user02 -G sftpusers \
  && adduser -D user03 -G sftpusers \
  && adduser -D user04 -G sftpusers \
  && adduser -D user05 -G sftpusers \
  && adduser -D user06 -G sftpusers \
  && adduser -D user07 -G sftpusers \
  && adduser -D user08 -G sftpusers \
  && adduser -D user09 -G sftpusers \
  && adduser -D user10 -G sftpusers \
# unlock the users (but dont set a password)
  && passwd -u user01 \
  && passwd -u user02 \
  && passwd -u user03 \
  && passwd -u user04 \
  && passwd -u user05 \
  && passwd -u user06 \
  && passwd -u user07 \
  && passwd -u user08 \
  && passwd -u user09 \
  && passwd -u user10 \
# create a keys directory for the users authorized_keys
  && mkdir -p /keys/user/user01 \
  && mkdir -p /keys/user/user02 \
  && mkdir -p /keys/user/user03 \
  && mkdir -p /keys/user/user04 \
  && mkdir -p /keys/user/user05 \
  && mkdir -p /keys/user/user06 \
  && mkdir -p /keys/user/user07 \
  && mkdir -p /keys/user/user08 \
  && mkdir -p /keys/user/user09 \
  && mkdir -p /keys/user/user10 \
# set passwords
  && echo 'user01:password01' | chpasswd \
  && echo 'user02:password02' | chpasswd \
  && echo 'user03:password03' | chpasswd \
  && echo 'user04:password04' | chpasswd \
  && echo 'user05:password05' | chpasswd \
  && echo 'user06:password06' | chpasswd \
  && echo 'user07:password07' | chpasswd \
  && echo 'user08:password08' | chpasswd \
  && echo 'user09:password09' | chpasswd \
  && echo 'user10:password10' | chpasswd

COPY ./entrypoint.sh /entrypoint.sh

# copy users pub keys into authorized_keys files
COPY ./keys/user/user01.pub /keys/user/user01/authorized_keys
COPY ./keys/user/user02.pub /keys/user/user02/authorized_keys
COPY ./keys/user/user03.pub /keys/user/user03/authorized_keys
COPY ./keys/user/user04.pub /keys/user/user04/authorized_keys
COPY ./keys/user/user05.pub /keys/user/user05/authorized_keys
COPY ./keys/user/user06.pub /keys/user/user06/authorized_keys
COPY ./keys/user/user07.pub /keys/user/user07/authorized_keys
COPY ./keys/user/user08.pub /keys/user/user08/authorized_keys
COPY ./keys/user/user09.pub /keys/user/user09/authorized_keys
COPY ./keys/user/user10.pub /keys/user/user10/authorized_keys

# copy SSH host keypairs
COPY ./keys/host/ /keys/host/

COPY ./sshd_config /etc/ssh/

# supervisord conf
COPY ./supervisord.conf /etc/supervisor/supervisord.conf

EXPOSE 22

CMD ["/entrypoint.sh"]
