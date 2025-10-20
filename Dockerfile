FROM node:20-alpine

# Install build deps for native modules (sqlite3)
RUN apk add --no-cache --virtual .build-deps python3 make g++

WORKDIR /app

# Install deps using only package.json (no lockfile)
COPY package.json ./
RUN npm install --omit=dev --no-audit --no-fund

# Copy app source after deps (better layer caching)
COPY . .

ENV NODE_ENV=production
EXPOSE 3000

# Optionally remove build deps to shrink image
RUN apk del .build-deps

CMD ["node", "server.cjs"]
