FROM ghcr.io/dependabot/dependabot-updater-core
ARG COMPOSER_V1_VERSION=1.10.26
ARG COMPOSER_V2_VERSION=2.5.5
ENV COMPOSER_ALLOW_SUPERUSER=1
RUN apt-get update \
  && apt-get upgrade -y \
  && apt-get install -y --no-install-recommends \
    software-properties-common
RUN add-apt-repository ppa:ondrej/php \
  && apt-get update \
  && apt-get install -y --no-install-recommends \
    php7.4 \
    php7.4-apcu \
    php7.4-bcmath \
    php7.4-cli \
    php7.4-common \
    php7.4-curl \
    php7.4-gd \
    php7.4-geoip \
    php7.4-gettext \
    php7.4-gmp \
    php7.4-imagick \
    php7.4-imap \
    php7.4-intl \
    php7.4-json \
    php7.4-ldap \
    php7.4-mbstring \
    php7.4-memcached \
    php7.4-mongodb \
    php7.4-mysql \
    php7.4-redis \
    php7.4-soap \
    php7.4-sqlite3 \
    php7.4-tidy \
    php7.4-xml \
    php7.4-zip \
    php7.4-zmq \
    php7.4-mcrypt \
    php7.4-amqp \
    php7.4-ds \
    php7.4-decimal \
    php7.4-protobuf \
    php7.4-ssh2 \
    php7.4-yaml \
    
    php8.0 \
    php8.0-apcu \
    php8.0-bcmath \
    php8.0-cli \
    php8.0-common \
    php8.0-curl \
    php8.0-gd \
    php8.0-gettext \
    php8.0-gmp \
    php8.0-imagick \
    php8.0-imap \
    php8.0-intl \
    php8.0-ldap \
    php8.0-mbstring \
    php8.0-memcached \
    php8.0-mongodb \
    php8.0-mysql \
    php8.0-redis \
    php8.0-soap \
    php8.0-sqlite3 \
    php8.0-tidy \
    php8.0-xml \
    php8.0-zip \
    php8.0-zmq \
    php8.0-mcrypt \
    php8.0-amqp \
    php8.0-ds \
    php8.0-decimal \
    php8.0-protobuf \
    php8.0-ssh2 \
    php8.0-yaml \

    php8.1 \
    php8.1-apcu \
    php8.1-bcmath \
    php8.1-cli \
    php8.1-common \
    php8.1-curl \
    php8.1-gd \
    php8.1-gettext \
    php8.1-gmp \
    php8.1-imagick \
    php8.1-imap \
    php8.1-intl \
    php8.1-ldap \
    php8.1-mbstring \
    php8.1-memcached \
    php8.1-mongodb \
    php8.1-mysql \
    php8.1-redis \
    php8.1-soap \
    php8.1-sqlite3 \
    php8.1-tidy \
    php8.1-xml \
    php8.1-zip \
    php8.1-zmq \
    php8.1-mcrypt \
    php8.1-amqp \
    php8.1-ds \
    php8.1-decimal \
    php8.1-protobuf \
    php8.1-ssh2 \
    php8.1-yaml \

    php8.2 \
    php8.2-apcu \
    php8.2-bcmath \
    php8.2-cli \
    php8.2-common \
    php8.2-curl \
    php8.2-gd \
    php8.2-gettext \
    php8.2-gmp \
    php8.2-imagick \
    php8.2-imap \
    php8.2-intl \
    php8.2-ldap \
    php8.2-mbstring \
    php8.2-memcached \
    php8.2-mongodb \
    php8.2-mysql \
    php8.2-redis \
    php8.2-soap \
    php8.2-sqlite3 \
    php8.2-tidy \
    php8.2-xml \
    php8.2-zip \
    php8.2-zmq \
    php8.2-mcrypt \
    php8.2-amqp \
    php8.2-ds \
    php8.2-decimal \
    php8.2-protobuf \
    php8.2-ssh2 \
    php8.2-yaml \
  && rm -rf /var/lib/apt/lists/*

RUN curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer1 --version=${COMPOSER_V1_VERSION}
RUN curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer --version=${COMPOSER_V2_VERSION}

USER dependabot
# Perform a fake `composer update` to warm ~/dependabot/.cache/composer/repo
# with historic data (we don't care about package files here)
RUN mkdir /tmp/composer-cache \
  && cd /tmp/composer-cache \
  && echo '{"require":{"psr/log": "^1.1.3"}}' > composer.json \
  && composer update --no-scripts --dry-run \
  && cd /tmp \
  && rm -rf /home/dependabot/.cache/composer/files \
  && rm -rf /tmp/composer-cache

COPY --chown=dependabot:dependabot composer/helpers /opt/composer/helpers
RUN update-alternatives --query php
RUN su root -s /bin/bash -c "update-alternatives --set php /usr/bin/php7.4" && bash /opt/composer/helpers/v1/build
RUN su root -s /bin/bash -c "update-alternatives --auto php" && /opt/composer/helpers/v2/build

COPY --chown=dependabot:dependabot composer $DEPENDABOT_HOME/composer
COPY --chown=dependabot:dependabot common $DEPENDABOT_HOME/common
COPY --chown=dependabot:dependabot updater $DEPENDABOT_HOME/dependabot-updater
