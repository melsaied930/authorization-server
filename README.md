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

1. **Clone the Repository**  
   Clone this project from your version control system:

   ```bash
   git clone <your-repository-url>
   cd authorization-server
   ```

2. **Build the Project**  
   Use Maven to build the project:

   ```bash
   mvn clean install
   ```

3. **Run the Application**  
   You can run the application using Maven:

   ```bash
   mvn spring-boot:run
   ```

   The server will start at `http://localhost:8080`.

---

## Configuration

### Maven Dependencies

The project uses the following dependencies:
- `spring-boot-starter-security`: Adds Spring Security for securing the application.
- `spring-boot-starter-web`: Provides web functionalities for the authorization server.
- `spring-security-oauth2-authorization-server`: Adds OAuth2 authorization server support.
- `nimbus-jose-jwt`: Provides JWT handling.

These dependencies are managed in `pom.xml`:

```xml
<project>
   <dependency>
       <groupId>org.springframework.security</groupId>
       <artifactId>spring-security-oauth2-authorization-server</artifactId>
   </dependency>
   <dependency>
       <groupId>com.nimbusds</groupId>
       <artifactId>nimbus-jose-jwt</artifactId>
       <version>9.40</version>
   </dependency>
</project>
```

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

## Project Structure

- **`AuthorizationServerConfig`**: Configures the security settings, token generation, and registered clients.
- **JWT Token Generation**: Uses the Nimbus library to generate and sign JWTs.
- **In-Memory Client Repository**: Stores the registered client with credentials and scopes.

---

## Code Snippet for `AuthorizationServerConfig`

```java
@Bean
public RegisteredClientRepository registeredClientRepository(PasswordEncoder passwordEncoder) {
    RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId("client-id")
            .clientSecret(passwordEncoder.encode("client-secret"))
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
            .scope("read")
            .scope("write")
            .tokenSettings(TokenSettings.builder()
                    .accessTokenTimeToLive(Duration.ofHours(1))
                    .build())
            .build();

    return new InMemoryRegisteredClientRepository(registeredClient);
}
```

---

## Running Tests

JUnit tests ensure the application is working as expected. A sample test for token creation is shown below:

```java
@Test
public void shouldReturnJwtToken() throws Exception {
    mockMvc.perform(post("/oauth2/token")
            .with(httpBasic("client-id", "client-secret"))
            .param("grant_type", "client_credentials")
            .param("scope", "read write"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.token_type").value("Bearer"))
            .andExpect(jsonPath("$.access_token").exists());
}
```

Run tests using:

```bash
mvn test
```

---

## License

This project is licensed under the MIT License. See the [LICENSE] file for details.

---

## Troubleshooting

If you encounter issues, make sure the dependencies are correctly installed by running:

```bash
mvn dependency:resolve
```

If a port conflict occurs, change the port by modifying `application.properties`:

```properties
server.port=8081
```

---

This README provides all the necessary information to set up and run the OAuth2 Authorization Server with Spring Boot. Feel free to modify the code as per your project requirements.