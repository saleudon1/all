# Use an official Node runtime as a parent image
FROM node:20-alpine

# Create app directory
WORKDIR /app

# Install app dependencies
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev

# Bundle app source
COPY . .

# Fly.io will provide PORT, default to 8080
ENV PORT=8080

# Expose the port Fly will proxy to
EXPOSE 8080

# Run the web service
CMD ["npm", "start"]
