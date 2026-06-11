# Auth API

A REST API for user authentication built with **Spring Boot 3** and **Java 21**. Handles registration, login, and JWT-based access control with role management.

---

## Features

- User registration & login
- JWT authentication (HS256)
- Role-based access control (`ROLE_USER`, `ROLE_ADMIN`)
- BCrypt password hashing
- User status tracking (`isActive`, `createdAt`, `updatedAt`)
- Centralized error handling
- Log rotation (daily log files)

---

## Prerequisites

- **JDK** 21+
- **Maven** 3.8+
- **MySQL** 8+

---

## Configuration

### 1. Create a `.env` file at the project root

```env
JWT_SECURITY_KEY=your_base64_encoded_secret_key_here
JWT_EXPIRATION=86400000
```

To generate a valid Base64 key (32+ bytes):
```bash
openssl rand -base64 32
```

### 2. Edit `src/main/resources/application.properties`

```properties
# Database
spring.datasource.url=jdbc:mysql://localhost:3306/authenticationapi_db?createDatabaseIfNotExist=true
spring.datasource.username=root
spring.datasource.password=yourpassword
```

### 3. Seed the roles table

The `roles` table must be populated before the first registration:

```sql
INSERT INTO roles (name) VALUES ('ROLE_USER');
INSERT INTO roles (name) VALUES ('ROLE_ADMIN');
```

---

## Running the Application

```bash
cd auth-api1
mvn spring-boot:run
```

The API will be available at `http://localhost:8080`.

---

## API Endpoints

All routes are prefixed with `/api/v1/auth`.

### Register

```
POST /api/v1/auth/register
```

Body:
```json
{
  "username": "jean",
  "email": "jean@example.com",
  "password": "secret123"
}
```

Response:
```json
{
  "responseCode": 200,
  "responseMessage": "SUCCESS",
  "data": {
    "username": "jean",
    "email": "jean@example.com"
  }
}
```

### Login

```
POST /api/v1/auth/login
```

Body:
```json
{
  "email": "jean@example.com",
  "password": "secret123"
}
```

Response:
```json
{
  "responseCode": 200,
  "responseMessage": "SUCCESS",
  "data": {
    "username": "jean",
    "email": "jean@example.com",
    "roles": ["ROLE_ADMIN"],
    "access_token": "<jwt>",
    "token_type": "Bearer"
  }
}
```

### Get Current User *(requires authentication)*

```
GET /api/v1/auth/users
Authorization: Bearer <jwt>
```

Response:
```json
{
  "responseCode": 200,
  "responseMessage": "SUCCESS",
  "data": {
    "id": 1,
    "username": "jean",
    "email": "jean@example.com",
    "isActive": true,
    "roles": ["ROLE_ADMIN"]
  }
}
```

---

## Project Structure

```
auth-api1/
└── src/main/java/com/authenticationsystem/auth_api/
    ├── web/
    │   └── AuthController.java
    ├── services/
    │   └── AuthService.java
    ├── security/
    │   ├── WebSecurityConfig.java
    │   ├── PasswordEncoderConfig.java
    │   ├── UserDetailsImpl.java
    │   └── UserDetailsServiceImpl.java
    ├── securityJwt/
    │   ├── JwtUtils.java
    │   ├── AuthTokenFilter.java
    │   └── AuthEntryPointJwt.java
    ├── models/
    │   ├── User.java
    │   ├── Role.java
    │   └── ERole.java
    ├── repositories/
    │   ├── UserRepository.java
    │   └── RoleRepository.java
    ├── dto/
    │   ├── LoginRequest.java
    │   ├── LoginResponse.java
    │   ├── RegisterRequest.java
    │   ├── RegisterUserResponse.java
    │   └── UserResponse.java
    ├── utils/
    │   └── Response.java
    └── advice_web/
        ├── ErrorHandler.java
        ├── BadRequestCustomException.java
        ├── DataExistException.java
        └── NotFoundException.java
```

---

## Tech Stack

| | |
|---|---|
| Language | Java 21 |
| Framework | Spring Boot 3 |
| Security | Spring Security + JWT (jjwt 0.11.5) |
| Database | MySQL + Spring Data JPA |
| Env variables | dotenv-java 3.2.0 |
| Utilities | Lombok, Bean Validation |
| Build | Maven |

---

## Bugs to Fix Before Running

### 1. Invalid test dependencies in `pom.xml`

These artifacts don't exist on Maven Central — the build will fail:

```xml
<!-- ❌ Remove these 4 dependencies -->
<artifactId>spring-boot-starter-data-jpa-test</artifactId>
<artifactId>spring-boot-starter-security-test</artifactId>
<artifactId>spring-boot-starter-validation-test</artifactId>
<artifactId>spring-boot-starter-webmvc-test</artifactId>

<!-- ✅ Replace with -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-test</artifactId>
    <scope>test</scope>
</dependency>
```

### 2. `AuthTokenFilter` instantiated with `null` in `WebSecurityConfig`

```java
// ❌ jwtUtils is null — will throw NullPointerException on every request
return new AuthTokenFilter(null, userDetailsService);

// ✅ Inject AuthTokenFilter directly instead
@RequiredArgsConstructor
public class WebSecurityConfig {
    private final AuthTokenFilter authTokenFilter;
    // ...
    http.addFilterBefore(authTokenFilter, UsernamePasswordAuthenticationFilter.class);
}
```

### 3. JWT expiration is hardcoded and ignores the `.env` value

```java
// ❌ expirationValue is read but never used — token expires in 78 min regardless
int expirationValue = Integer.valueOf(jwtExpirationMs);
.setExpiration(new Date(new Date().getTime() + 4680000))

// ✅ Use the variable
.setExpiration(new Date(new Date().getTime() + expirationValue))
```

### 4. Every new user is assigned `ROLE_ADMIN` by default

```java
// ❌ All registered users become admins
Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)...

// ✅ Default new users to ROLE_USER
Role userRole = roleRepository.findByName(ERole.ROLE_USER)...
```
