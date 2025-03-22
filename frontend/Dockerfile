# Stage 1: Build the Flutter web app
FROM ubuntu:22.04 AS builder

# Avoid tzdata interactive setup
ENV DEBIAN_FRONTEND=noninteractive

# Install required dependencies
RUN apt-get update && apt-get install -y \
    curl \
    git \
    unzip \
    xz-utils \
    zip \
    libglu1-mesa \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user
RUN useradd -ms /bin/bash developer
USER developer
WORKDIR /home/developer

# Download Flutter SDK
RUN git clone -b stable https://github.com/flutter/flutter.git

# Add flutter to PATH
ENV PATH="/home/developer/flutter/bin:${PATH}"

# Run flutter doctor and enable web
RUN flutter doctor && \
    flutter config --no-analytics && \
    flutter config --enable-web

# Set up app directory
WORKDIR /home/developer/app

# Copy pubspec files
COPY --chown=developer:developer pubspec.yaml ./

# Get packages
RUN flutter pub get

# Copy the rest of the app source
COPY --chown=developer:developer . .

# Build web app
RUN flutter build web --release

# Stage 2: Serve the app using nginx
FROM nginx:alpine

# Copy the built app to nginx
COPY --from=builder /home/developer/app/build/web /usr/share/nginx/html

# Copy nginx configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Expose port 80
EXPOSE 80

CMD ["nginx", "-g", "daemon off;"] 