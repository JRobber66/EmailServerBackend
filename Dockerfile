FROM node:20-bookworm-slim

RUN apt-get update && apt-get install -y python3 build-essential \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package.json ./
RUN npm install --omit=dev --no-audit --no-fund

COPY . .
ENV NODE_ENV=production
EXPOSE 3000
CMD ["node","server.cjs"]
