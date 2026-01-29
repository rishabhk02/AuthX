# AuthX - Distributed Authentication & Authorization Platform

![Java](https://img.shields.io/badge/Java-21-orange?style=flat-square&logo=openjdk)
![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.5.9-brightgreen?style=flat-square&logo=spring)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15-blue?style=flat-square&logo=postgresql)
![Redis](https://img.shields.io/badge/Redis-7-red?style=flat-square&logo=redis)
![RabbitMQ](https://img.shields.io/badge/RabbitMQ-3-orange?style=flat-square&logo=rabbitmq)
![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)

A production-ready, enterprise-grade authentication and authorization service built with Spring Boot. AuthX provides secure user authentication, role-based access control (RBAC), OAuth2 integration, and distributed session management.

## 📋 Table of Contents

- [Purpose](#-purpose)
- [Features](#-features)
- [Technology Stack](#-technology-stack)
- [Architecture](#-architecture)
- [Prerequisites](#-prerequisites)
- [Installation & Setup](#-installation--setup)
- [Configuration](#-configuration)
- [Running the Application](#-running-the-application)
- [API Documentation](#-api-documentation)
- [Project Structure](#-project-structure)
- [Security Features](#-security-features)
- [License](#-license)

## 🎯 Purpose

AuthX is designed to provide a centralized, scalable authentication and authorization solution for modern distributed applications. It eliminates the need to implement authentication logic in every microservice by offering:

- **Centralized Authentication**: Single source of truth for user credentials and permissions
- **Distributed Session Management**: Token-based authentication with Redis caching
- **Multi-tenant Ready**: Support for role-based and permission-based access control
- **Third-party Integration**: Seamless integration with OAuth2 providers (Google, etc.)
- **Asynchronous Operations**: Non-blocking email notifications via RabbitMQ
- **Production-Ready**: Built with industry best practices and security standards

## ✨ Features

### Authentication
- ✅ User registration with email verification
- ✅ Email/password login with JWT tokens
- ✅ Google OAuth2 authentication
- ✅ OTP-based two-factor authentication
- ✅ Password reset with secure tokens
- ✅ Refresh token rotation
- ✅ Token blacklisting on logout
- ✅ All login device tracking

### Authorization
- ✅ Role-Based Access Control (RBAC)
- ✅ Fine-grained permission management
- ✅ Dynamic role and permission assignment
- ✅ Pre-authorization with Spring Security

### Security
- ✅ JWT with RS256 asymmetric encryption
- ✅ Password hashing with BCrypt
- ✅ Redis-based token blacklist
- ✅ Email verification before activation
- ✅ Secure password reset workflow
- ✅ Request rate limiting (configurable)

### Infrastructure
- ✅ Asynchronous email delivery via RabbitMQ
- ✅ SendGrid integration for transactional emails
- ✅ Redis caching for session management
- ✅ PostgreSQL for persistent storage
- ✅ Docker containerization
- ✅ Health check endpoints

### Developer Experience
- ✅ Comprehensive Swagger/OpenAPI documentation
- ✅ Structured error handling
- ✅ Validation with Jakarta Bean Validation
- ✅ Clean architecture with separation of concerns
- ✅ Interface-based design for testability

## 🛠 Technology Stack

### Backend Framework
- **Java 21** - Latest LTS version with virtual threads support
- **Spring Boot 3.5.9** - Application framework
- **Spring Security 6.2** - Authentication & authorization
- **Spring Data JPA** - Data persistence
- **Hibernate** - ORM framework

### Database & Caching
- **PostgreSQL 15** - Primary relational database
- **Redis 7** - In-memory cache and token blacklist
- **HikariCP** - High-performance JDBC connection pool

### Message Queue
- **RabbitMQ 3** - Asynchronous message broker
- **Spring AMQP** - RabbitMQ integration

### Security & Authentication
- **JWT (JSON Web Tokens)** - Stateless authentication
- **RS256 Algorithm** - Asymmetric encryption
- **BCrypt** - Password hashing
- **Google OAuth2** - Third-party authentication

### Email & Communication
- **SendGrid** - Transactional email service
- **Email Templates** - HTML/Text email support

### Documentation & Testing
- **Swagger/OpenAPI 3** - API documentation
- **SpringDoc OpenAPI** - Auto-generated API docs
- **JUnit 5** - Unit testing framework
- **Mockito** - Mocking framework

### Build & DevOps
- **Maven 3.9+** - Build automation
- **Docker & Docker Compose** - Containerization
- **Spring Boot DevTools** - Hot reload for development
- **Lombok** - Boilerplate code reduction

## 🏗 Architecture

AuthX follows a **layered architecture** with clear separation of concerns:

```
┌─────────────────────────────────────────────────┐
│              Controller Layer                    │
│  (REST APIs, Request/Response Handling)         │
└─────────────────┬───────────────────────────────┘
                  │
┌─────────────────▼───────────────────────────────┐
│           Service Interface Layer                │
│  (Business Logic Contracts)                      │
└─────────────────┬───────────────────────────────┘
                  │
┌─────────────────▼───────────────────────────────┐
│         Service Implementation Layer             │
│  (Core Business Logic)                           │
└─────────────────┬───────────────────────────────┘
                  │
┌─────────────────▼───────────────────────────────┐
│            Integration Layer                     │
│  (Third-party Services: SendGrid, Google OAuth) │
└─────────────────┬───────────────────────────────┘
                  │
┌─────────────────▼───────────────────────────────┐
│            Repository Layer                      │
│  (Data Access with Spring Data JPA)             │
└─────────────────┬───────────────────────────────┘
                  │
┌─────────────────▼───────────────────────────────┐
│              Database Layer                      │
│  (PostgreSQL, Redis)                             │
└─────────────────────────────────────────────────┘
```

### Key Design Patterns
- **Dependency Inversion Principle**: Controllers depend on service interfaces, not implementations
- **Service Layer Pattern**: Business logic isolated from controllers
- **Repository Pattern**: Data access abstraction via Spring Data JPA
- **Integration Layer**: Third-party services decoupled from core business logic
- **DTO Pattern**: Separate request/response models from domain entities

## 📦 Prerequisites

Before you begin, ensure you have the following installed:

- **Java Development Kit (JDK) 21** or higher
  ```bash
  java -version
  ```

- **Maven 3.9+**
  ```bash
  mvn -version
  ```

- **Docker & Docker Compose** (for running infrastructure services)
  ```bash
  docker --version
  docker-compose --version
  ```

- **Git**
  ```bash
  git --version
  ```

### External Services (Optional but Recommended)
- **SendGrid Account** - For email functionality ([Sign up here](https://sendgrid.com/))
- **Google Cloud Console** - For OAuth2 authentication ([Setup guide](https://console.cloud.google.com/))

## 🚀 Installation & Setup

### 1. Clone the Repository

```bash
git clone https://github.com/rishabhk02/authx.git
cd authx
```

### 2. Generate RSA Keys for JWT

Create RSA private and public keys for JWT signing:

```bash
# Create keys directory
mkdir -p src/main/resources/keys

# Generate private key
openssl genrsa -out src/main/resources/keys/private.pem 2048

# Generate public key
openssl rsa -in src/main/resources/keys/private.pem -pubout -out src/main/resources/keys/public.pem
```

### 3. Start Infrastructure Services

Use Docker Compose to start PostgreSQL, Redis, and RabbitMQ:

```bash
# Start all services in detached mode
docker-compose -f docker-compose.dev.yml up -d

# Verify services are running
docker-compose -f docker-compose.dev.yml ps
```

This will start:
- **PostgreSQL** on `localhost:5432`
- **Redis** on `localhost:6379`
- **RabbitMQ** on `localhost:5672` (AMQP) and `localhost:15672` (Management UI)

### 4. Configure Environment Variables

Create a `.env` file in the project root or set environment variables:

```bash
# Database Configuration
DB_URL=jdbc:postgresql://localhost:5432/authx?useSSL=false&allowPublicKeyRetrieval=true
DB_USER=authx_user
DB_PASSWORD=password123

# Redis Configuration
REDIS_HOST=localhost
REDIS_PORT=6379

# RabbitMQ Configuration
RABBITMQ_HOST=localhost
RABBITMQ_PORT=5672
RABBITMQ_USERNAME=guest
RABBITMQ_PASSWORD=guest

# SendGrid Email Configuration
SENDGRID_API_KEY=your-sendgrid-api-key
SENDGRID_FROM_EMAIL=noreply@yourdomain.com

# Frontend URLs (for email links)
EMAIL_VERIFICATION_URL=http://localhost:3000/verify-email
FE_LOGIN_URL=http://localhost:3000/login
PASSWORD_RESET_URL=http://localhost:3000/reset-password

# Google OAuth2 Configuration
GOOGLE_CLIENT_ID=your-google-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-google-client-secret
```

> **Note**: Default values are provided in `application.yml`. You only need to set environment variables for production or if you want to override defaults.

### 5. Build the Project

```bash
# Clean and build
mvn clean package

# Or build without running tests
mvn clean package -DskipTests
```

## ⚙️ Configuration

### Application Configuration

The main configuration file is located at `src/main/resources/application.yml`.

#### Key Configuration Sections:

**Database Configuration:**
```yaml
spring:
  datasource:
    url: ${DB_URL:jdbc:postgresql://localhost:5432/authx}
    username: ${DB_USER:authx_user}
    password: ${DB_PASSWORD:password123}
```

**JWT Token Expiration:**
```yaml
jwt:
  expiration:
    access: 900000          # 15 minutes
    refresh: 604800000      # 7 days
    email-verification: 3600000  # 1 hour
    password-reset: 1800000 # 30 minutes
```

**Redis Configuration:**
```yaml
spring:
  data:
    redis:
      host: ${REDIS_HOST:localhost}
      port: ${REDIS_PORT:6379}
```

**RabbitMQ Configuration:**
```yaml
spring:
  rabbitmq:
    host: ${RABBITMQ_HOST:localhost}
    port: ${RABBITMQ_PORT:5672}
    username: ${RABBITMQ_USERNAME:guest}
    password: ${RABBITMQ_PASSWORD:guest}
```

## 🏃 Running the Application

### Development Mode

```bash
# Run with Maven (includes hot reload)
mvn spring-boot:run
```

### Production Mode

```bash
# Build the JAR
mvn clean package

# Run the JAR
java -jar target/authx-0.0.1-SNAPSHOT.jar
```

### Using Docker

```bash
# Build Docker image
docker build -t authx:latest .

# Run with Docker Compose (includes all services)
docker-compose up -d
```

### Verify Application is Running

- **Application**: http://localhost:8080
- **Swagger UI**: http://localhost:8080/swagger-ui.html
- **Health Check**: http://localhost:8080/actuator/health
- **RabbitMQ Management**: http://localhost:15672 (guest/guest)

## 📚 API Documentation

### Swagger/OpenAPI

Once the application is running, access the interactive API documentation:

**Swagger UI**: [http://localhost:8080/swagger-ui.html](http://localhost:8080/swagger-ui.html)

**OpenAPI JSON**: [http://localhost:8080/v3/api-docs](http://localhost:8080/v3/api-docs)

### Main API Endpoints

#### Authentication Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | `/auth/register` | Register new user | No |
| POST | `/auth/login` | Login with credentials | No |
| POST | `/auth/verify-otp` | Verify OTP for 2FA | No |
| GET | `/auth/verify-email` | Verify email with token | No |
| POST | `/auth/google` | Login with Google OAuth | No |
| POST | `/auth/forgot-password` | Request password reset | No |
| POST | `/auth/reset-password` | Reset password with token | No |
| POST | `/auth/refresh` | Refresh access token | Yes |
| POST | `/auth/logout` | Logout and blacklist token | Yes |

#### User Management Endpoints

| Method | Endpoint | Description | Auth Required | Role |
|--------|----------|-------------|---------------|------|
| PUT | `/auth/update-password` | Update password | Yes | USER |
| GET | `/auth/users/{id}` | Get user details | Yes | ADMIN |
| POST | `/auth/users/{id}/roles` | Assign roles to user | Yes | ADMIN |
| POST | `/auth/users/{id}/permissions` | Assign permissions | Yes | ADMIN |

#### Health & Monitoring

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/actuator/health` | Application health status |
| GET | `/actuator/info` | Application information |

## 📁 Project Structure

```
authx/
├── src/
│   ├── main/
│   │   ├── java/com/authx/
│   │   │   ├── config/              # Configuration classes
│   │   │   │   ├── JwtKeyConfig.java
│   │   │   │   ├── RabbitMQConfig.java
│   │   │   │   ├── SecurityConfig.java
│   │   │   │   └── SwaggerConfig.java
│   │   │   ├── constants/           # Application constants
│   │   │   │   └── AppConstants.java
│   │   │   ├── controller/          # REST controllers
│   │   │   │   └── AuthController.java
│   │   │   ├── dto/                 # Data Transfer Objects
│   │   │   │   ├── request/         # Request DTOs
│   │   │   │   └── response/        # Response DTOs
│   │   │   ├── entity/              # JPA entities
│   │   │   │   ├── User.java
│   │   │   │   ├── Role.java
│   │   │   │   ├── Permission.java
│   │   │   │   ├── Token.java
│   │   │   │   └── OTPRequest.java
│   │   │   ├── enums/               # Enumerations
│   │   │   │   ├── TokenPurpose.java
│   │   │   │   └── AuthProvider.java
│   │   │   ├── exception/           # Custom exceptions
│   │   │   │   └── GlobalExceptionHandler.java
│   │   │   ├── integration/         # Third-party integrations
│   │   │   │   ├── email/
│   │   │   │   │   └── SendGridService.java
│   │   │   │   └── oauth/
│   │   │   │       └── GoogleTokenVerificationService.java
│   │   │   ├── repository/          # Spring Data JPA repositories
│   │   │   │   ├── UserRepository.java
│   │   │   │   ├── RoleRepository.java
│   │   │   │   ├── PermissionRepository.java
│   │   │   │   ├── TokenRepository.java
│   │   │   │   └── OTPRequestRepository.java
│   │   │   ├── security/            # Security components
│   │   │   │   ├── CustomUserDetailsService.java
│   │   │   │   ├── JwtAuthenticationFilter.java
│   │   │   │   ├── SecurityConfig.java
│   │   │   │   └── UserPrincipal.java
│   │   │   ├── service/
│   │   │   │   ├── interfaces/      # Service contracts
│   │   │   │   │   ├── IAuthService.java
│   │   │   │   │   ├── IUserService.java
│   │   │   │   │   ├── ITokenService.java
│   │   │   │   │   ├── IEmailService.java
│   │   │   │   │   ├── IGoogleAuthService.java
│   │   │   │   │   └── IGoogleTokenVerificationService.java
│   │   │   │   ├── impl/            # Service implementations
│   │   │   │   │   ├── AuthService.java
│   │   │   │   │   ├── UserService.java
│   │   │   │   │   ├── TokenService.java
│   │   │   │   │   └── GoogleAuthService.java
│   │   │   │   ├── email/
│   │   │   │   │   └── EmailConsumerService.java
│   │   │   │   ├── DataInitializationService.java
│   │   │   │   ├── RabbitMQService.java
│   │   │   │   ├── RedisTokenBlacklistService.java
│   │   │   │   └── TokenBlacklistService.java
│   │   │   ├── util/                # Utility classes
│   │   │   │   ├── EmailTemplates.java
│   │   │   │   └── ValidationUtils.java
│   │   │   └── AuthxApplication.java
│   │   └── resources/
│   │       ├── application.yml      # Application configuration
│   │       ├── application.properties
│   │       └── keys/                # RSA keys for JWT
│   │           ├── private.pem
│   │           └── public.pem
│   └── test/                        # Unit tests
├── docker-compose.yml               # Production Docker Compose
├── docker-compose.dev.yml           # Development Docker Compose
├── Dockerfile                       # Application Dockerfile
├── pom.xml                          # Maven configuration
├── .gitignore
└── README.md
```

## 🔒 Security Features

### JWT Token Management
- **RS256 Algorithm**: Asymmetric encryption with RSA keys
- **Token Rotation**: Refresh tokens for long-lived sessions
- **Token Blacklisting**: Redis-based blacklist for logged-out tokens
- **Automatic Expiration**: Configurable token lifetimes

### Password Security
- **BCrypt Hashing**: Industry-standard password hashing
- **Minimum Requirements**: 8-64 characters
- **Secure Reset Flow**: Time-limited reset tokens

### Email Verification
- **Pre-activation Verification**: Users must verify email before login
- **Secure Tokens**: One-time use tokens with expiration
- **Resend Capability**: Users can request new verification emails

### Two-Factor Authentication
- **OTP Support**: Optional 2FA with time-based OTPs
- **Secure Delivery**: OTPs sent via email through RabbitMQ

### Role-Based Access Control
- **Fine-grained Permissions**: Separate roles and permissions
- **Pre-authorization**: Method-level security with `@PreAuthorize`
- **Dynamic Assignment**: Roles and permissions can be assigned at runtime

### API Security
- **CORS Configuration**: Configurable cross-origin resource sharing
- **Request Validation**: Jakarta Bean Validation on all inputs
- **Error Handling**: Structured error responses without sensitive data leakage


## 🐳 Docker Deployment

### Build Docker Image

```bash
docker build -t authx:latest .
```

### Run with Docker Compose

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f authx

# Stop all services
docker-compose down
```

### Environment Variables for Docker

Create a `.env` file in the project root:

```env
POSTGRES_DB=authx
POSTGRES_USER=authx_user
POSTGRES_PASSWORD=your_secure_password
RABBITMQ_USER=admin
RABBITMQ_PASSWORD=your_secure_password
SENDGRID_API_KEY=your_sendgrid_key
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_secret
```

## 📄 License

This project is licensed under the MIT License

## 🙏 Acknowledgments

- [Spring Boot](https://spring.io/projects/spring-boot)
- [Spring Security](https://spring.io/projects/spring-security)
- [SendGrid](https://sendgrid.com/)
- [Google OAuth2](https://developers.google.com/identity/protocols/oauth2)

---

**Made with ❤️ by [Rishabh Kumrawat](https://github.com/rishabhk02)**

**⭐ Star this repository if you find it helpful!**
