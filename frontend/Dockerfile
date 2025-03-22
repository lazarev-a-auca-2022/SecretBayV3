# Stage 1: Build the Flutter web app
FROM dart:stable AS builder

# Install git and required dependencies
RUN apt-get update && apt-get install -y \
    git \
    xz-utils \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user and set up directories
RUN useradd -ms /bin/bash developer && \
    mkdir -p /home/developer/.pub-cache && \
    mkdir -p /opt/flutter && \
    chown -R developer:developer /home/developer && \
    chown -R developer:developer /opt/flutter

# Set up environment variables
ENV PUB_CACHE=/home/developer/.pub-cache
ENV PATH="/opt/flutter/bin:${PATH}"
ENV HOME=/home/developer
ENV FLUTTER_HOME=/opt/flutter

# Switch to non-root user
USER developer
WORKDIR /home/developer

# Clone and set up Flutter
RUN git clone https://github.com/flutter/flutter.git ${FLUTTER_HOME} && \
    cd ${FLUTTER_HOME} && \
    git checkout stable

# Initialize Flutter with memory optimization
ENV FLUTTER_TOOLS_VM_OPTIONS="--old_gen_heap_size=512"
RUN dart --version && \
    flutter config --no-analytics && \
    flutter config --enable-web && \
    flutter doctor

# Set up app directory
WORKDIR /home/developer/app

# Copy pubspec files with correct ownership
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