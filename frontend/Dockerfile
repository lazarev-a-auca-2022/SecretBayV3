# Stage 1: Build the Flutter web app
FROM debian:bullseye AS builder

# Install dependencies
RUN apt-get update && apt-get install -y \
    curl \
    git \
    unzip \
    xz-utils \
    && rm -rf /var/lib/apt/lists/*

# Install Flutter
RUN git clone https://github.com/flutter/flutter.git /flutter
ENV PATH="/flutter/bin:${PATH}"
RUN flutter channel stable && flutter upgrade
RUN flutter config --enable-web

# Copy the app files
WORKDIR /app
COPY . .

# Get app dependencies and build for web
RUN flutter pub get
RUN flutter build web --release

# Stage 2: Serve the app using nginx
FROM nginx:alpine

# Copy the built app to nginx
COPY --from=builder /app/build/web /usr/share/nginx/html

# Copy nginx configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Expose port 80
EXPOSE 80

CMD ["nginx", "-g", "daemon off;"] 