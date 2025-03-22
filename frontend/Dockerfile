# Stage 1: Build the Flutter web app
FROM dart:stable AS builder

# Install Flutter
RUN git clone https://github.com/flutter/flutter.git /usr/local/flutter
ENV PATH="/usr/local/flutter/bin:${PATH}"
RUN flutter channel stable
RUN flutter doctor
RUN flutter config --enable-web

# Set working directory
WORKDIR /app

# Copy pubspec files
COPY pubspec.yaml ./

# Get packages
RUN flutter pub get

# Copy the rest of the app source
COPY . .

# Build web app
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