FROM php:8.1-apache

# Instalar dependencias necesarias
RUN apt-get update && apt-get install -y \
    libpng-dev \
    libjpeg-dev \
    libfreetype6-dev \
    libzip-dev \
    libicu-dev \
    libxml2-dev \
    libpq-dev \
    git \
    unzip \
    && docker-php-ext-configure gd --with-freetype --with-jpeg \
    && docker-php-ext-install -j$(nproc) gd zip intl soap opcache pgsql pdo_pgsql

# Descargar Moodle 4.4
RUN cd /var/www && \
    git clone -b MOODLE_404_STABLE --depth=1 https://github.com/moodle/moodle.git html && \
    mkdir -p /var/www/moodledata && \
    chown -R www-data:www-data /var/www/html /var/www/moodledata && \
    chmod -R 755 /var/www/moodledata

# Configurar Apache
RUN a2enmod rewrite headers

# Configurar Apache para confiar en el proxy inverso (Traefik)
RUN echo 'SetEnvIf X-Forwarded-Proto "https" HTTPS=on' >> /etc/apache2/apache2.conf

# Exponer puertos
EXPOSE 80 443

WORKDIR /var/www/html