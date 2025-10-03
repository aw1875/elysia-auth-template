# Elysia Auth Template

This is a template repository for setting up authentication in an Elysia application. This template uses JWT for authentication rather than sessions along with several other technologies to provide a robust authentication system.

### Technologies Used

- Bun
- Elysia
- JWT
- Zod
- MySQL
- Prisma ORM
- Redis

## Setup Instructions

Clone the repository and install dependencies:

```bash
git clone https://github.com/aw1875/elysia-auth-template.git
cd elysia-auth-template
bun install
```

Copy the `.env.example` file to `.env` and update the database connection string if not using the default docker connections.

Start the docker containers for MySQL and Redis:

```bash
docker compose up -d
```

Run the prisma migrations to set up the database schema:

```bash
bunx prisma migrate dev
```

Generate an HS256 key for JWT and set it as an environment variable:

```bash
openssl rand -base64 32 | tr '+/' '-_' | tr -d '=' # Generates a URL-safe base64 string
```

Be sure to add this to your `.env` file as `JWT_SECRET`.

Start the development server:

```bash
bun dev
```

## Inspecting data

Redis is currently configured ot use [RedisInsight](https://redis.io/insight/) which you can view at [http://localhost:5540](http://localhost:5540). You'll then want to add a new database with the following details:

- `Database Alias`: Your choise
- `Host`: host.docker.internal
- `Port`: 6379

[phpMyAdmin](https://www.phpmyadmin.net/) is also configured for viewing the MySQL database at [http://localhost:8080](http://localhost:8080). The default username is `root` and the password is `password` (if using the default docker values).

## API Endpoints

All endpoints are prefixed with `/api/v1`.

- `GET /docs`: OpenAPI documentation.
- `GET /health`: Health check endpoint.
- `POST /auth/signup`: User signup.
- `POST /auth/signin`: User signin.
- `POST /auth/signout`: User signout.
- `POST /auth/refresh`: Refresh JWT tokens.
- `GET /auth/session`: Get current user details (requires authentication).

## Notes

Currently, `host.docker.internal` is mapped to `172.17.0.1` in the docker-compose file. You may need to change this based on your docker setup (check the `default-address-pools`). On Linux, you can set this in the Docker daemon configuration file at: `/etc/docker/daemon.json`
