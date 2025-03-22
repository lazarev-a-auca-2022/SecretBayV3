# Stage 1: Build the Flutter web app
FROM dart:stable AS builder

# Create a non-root user
RUN useradd -ms /bin/bash developer

# Install git and required dependencies
RUN apt-get update && apt-get install -y \
    git \
    xz-utils \
    && rm -rf /var/lib/apt/lists/*

# Set up Flutter
RUN git clone https://github.com/flutter/flutter.git /opt/flutter
ENV PATH="/opt/flutter/bin:${PATH}"

# Give developer user access to Flutter
RUN chown -R developer:developer /opt/flutter

# Switch to non-root user
USER developer

# Initialize Flutter (with memory optimization flags)
ENV FLUTTER_TOOLS_VM_OPTIONS="--old_gen_heap_size=512"
RUN flutter precache
RUN flutter config --no-analytics
RUN flutter config --enable-web

# Set working directory
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