# Build stage
FROM node:20-alpine AS build
WORKDIR /app
COPY package.json ./
# When running inside compose, dependencies need to be installed here.
# (In local dev you would normally run `npm install` once on the host.)
RUN npm install --no-audit --no-fund || true
COPY . .
RUN npm run build

# Serve stage
FROM nginx:1.27-alpine
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 5173
CMD ["nginx", "-g", "daemon off;"]
