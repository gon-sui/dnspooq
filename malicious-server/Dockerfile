FROM nginx:alpine

# Create configuration directory
RUN mkdir -p /etc/nginx /usr/share/nginx/html

# Copy Nginx configuration and content
COPY nginx.conf /etc/nginx/nginx.conf
COPY fake-site/index.html /usr/share/nginx/html/

# Expose port 80
EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
