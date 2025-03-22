# Stage 1: Build the Flutter web app
FROM cirrusci/flutter:3.19.3 AS builder

# Set working directory
WORKDIR /app

# Copy pubspec files
COPY pubspec.yaml pubspec.lock ./

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