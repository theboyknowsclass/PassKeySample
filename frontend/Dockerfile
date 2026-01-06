# Build stage
FROM node:20-alpine AS build

WORKDIR /app

# Copy package files
COPY package.json ./

# Install dependencies
RUN npm install

# Copy source files
COPY . .

# Build the application
# VITE_ENABLE_PASSKEY_REGISTRATION defaults to 'true' if not set
ARG VITE_ENABLE_PASSKEY_REGISTRATION=true
ENV VITE_ENABLE_PASSKEY_REGISTRATION=${VITE_ENABLE_PASSKEY_REGISTRATION}
RUN npm run build

# Production stage with nginx
FROM nginx:alpine

# Copy built files from build stage
COPY --from=build /app/dist /usr/share/nginx/html

# Copy nginx configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Create SSL directory (certificates will be mounted as volumes)
RUN mkdir -p /etc/nginx/ssl

# Expose HTTPS port
EXPOSE 443

CMD ["nginx", "-g", "daemon off;"]

