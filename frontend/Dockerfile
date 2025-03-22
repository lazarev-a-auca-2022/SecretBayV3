# Stage 1: Build the Flutter web app
FROM us-docker.pkg.dev/flutter-404420/flutter-sdk/flutter:3.19.1 AS builder

# Set up app directory
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