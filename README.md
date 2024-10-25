# Authorization Server with Spring Boot

This project demonstrates how to build an OAuth2 Authorization Server using **Spring Boot**, **Spring Security**, and **OAuth2 Authorization Server** configuration. It supports generating JWT tokens using the client credentials grant type.

---

## Prerequisites

Ensure you have the following installed:

- Java 17 or later
- Maven 3.x
- A modern IDE like IntelliJ IDEA (Optional)

---

## Setup

1. **Build the Project**  
   Use Maven to build the project:

   ```bash
   mvn clean install
   ```

2. **Run the Application**  
   You can run the application using Maven:

   ```bash
   mvn spring-boot:run
   ```

   The server will start at `http://localhost:8080`.

---

## Test the Token Endpoint

Use the following **cURL** command to request a token using the **client credentials grant type**:

```bash
curl -X POST \
  -u client-id:client-secret \
  -d 'grant_type=client_credentials&scope=read write' \
  http://localhost:8080/oauth2/token
```

### Expected Response

```json
{
  "access_token": "<jwt-token>",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "read write"
}
```

---

This README provides all the necessary information to set up and run the OAuth2 Authorization Server with Spring Boot. Feel free to modify the code as per your project requirements.