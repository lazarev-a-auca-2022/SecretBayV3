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

# Set environment variables for Flutter
ENV FLUTTER_HOME=/home/developer/flutter
ENV PATH="$FLUTTER_HOME/bin:$PATH"
ENV PUB_CACHE=/home/developer/.pub-cache
ENV FLUTTER_TOOLS_VM_OPTIONS="--old_gen_heap_size=256"

# Download Flutter SDK and perform initial setup in smaller steps
RUN git clone -b stable --depth 1 https://github.com/flutter/flutter.git $FLUTTER_HOME && \
    flutter precache --no-android --no-ios --no-linux --no-windows --no-macos --no-fuchsia --web && \
    flutter config --no-analytics && \
    flutter config --enable-web && \
    rm -rf $PUB_CACHE

# Set up app directory
WORKDIR /home/developer/app

# Copy pubspec files
COPY --chown=developer:developer pubspec.yaml ./

# Get packages with reduced concurrency
RUN flutter pub get --no-offline

# Copy the rest of the app source
COPY --chown=developer:developer . .

# Build web app with memory limits
RUN flutter build web --release --dart-define=Dart_VM_Options=--old_gen_heap_size=256

# Stage 2: Serve the app using nginx
FROM nginx:alpine

# Copy the built app to nginx
COPY --from=builder /home/developer/app/build/web /usr/share/nginx/html

# Copy nginx configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Expose port 80
EXPOSE 80

CMD ["nginx", "-g", "daemon off;"] 