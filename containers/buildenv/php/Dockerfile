# syntax=docker/dockerfile:1
# PHP/Composer build environment on the shared native toolchain. php8.3-dev supplies phpize
# and php-config; autoconf/automake/libtool are what phpize-generated configure scripts need.
# PHP extensions therefore compile with the same gcc as every other family.
FROM appsec-review/buildenv-native-toolchain:noble-gcc13.3-clang18.1
LABEL org.opencontainers.image.title="audit-buildenv-php" \
      org.opencontainers.image.version="noble-php8.3.6-composer2.7.1"
USER 0:0
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      autoconf=2.71-3 automake=1:1.16.5-1.3ubuntu1 composer=2.7.1-2 libtool=2.4.7-7build1 \
      php8.3-cli=8.3.6-0ubuntu0.24.04.11 php8.3-dev=8.3.6-0ubuntu0.24.04.11 \
      php8.3-mbstring=8.3.6-0ubuntu0.24.04.11 php8.3-xml=8.3.6-0ubuntu0.24.04.11 \
      unzip=6.0-28ubuntu4.1 \
 && rm -rf /var/lib/apt/lists/* \
 && sh /opt/native-toolchain/check-toolchain.sh \
 && php --version | grep -F 'PHP 8.3.6' \
 && phpize --version | grep -F 'PHP Api Version' \
 && composer --version 2>/dev/null | grep -F 'Composer version 2.7.1'
ENV COMPOSER_HOME=/tmp/composer COMPOSER_ALLOW_SUPERUSER=0
ENTRYPOINT []
CMD []
USER 10001:10001
WORKDIR /workspace
