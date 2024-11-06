# Authorization Server with Spring Boot

This project demonstrates how to build an OAuth2 Authorization Server using **Spring Boot**, **Spring Security**, and **OAuth2 Authorization Server** configuration. It supports generating JWT tokens using the **Client Credentials** grant type.

---

## Prerequisites

Ensure the following tools are installed:

- **Java 17** or later
- **Maven 3.x**
- **IDE** like IntelliJ IDEA (Optional)

---

## Setup

### Step 1: Generate the Keystore

To generate the keystore file (`keystore.p12`) non-interactively, specify all parameters inline using the `-dname` and `-storepass` options. Here’s the command:

```bash
keytool -genkeypair \
  -alias keyserver \
  -keyalg RSA \
  -keysize 2048 \
  -storetype PKCS12 \
  -keystore src/main/resources/keystore.p12 \
  -storepass password \
  -keypass password \
  -validity 3650 \
  -dname "CN=localhost, OU=IT, O=MyCompany, L=City, ST=State, C=US"
```

#### Explanation:

- `-alias keyserver`: Alias for the key entry.
- `-keyalg RSA`: Specifies the RSA algorithm for the key.
- `-keysize 2048`: Sets the key size to 2048 bits.
- `-storetype PKCS12`: Uses the PKCS12 keystore type.
- `-keystore src/main/resources/keystore.p12`: Location to save the keystore.
- `-storepass password`: Password for the keystore (customizable).
- `-keypass password`: Password for the private key (can differ from keystore password).
- `-validity 3650`: Certificate validity (10 years).
- `-dname`: Specifies the distinguished name for the certificate:
   - `CN`: Common Name (e.g., localhost).
   - `OU`: Organizational Unit.
   - `O`: Organization.
   - `L`: City.
   - `ST`: State.
   - `C`: Country (2-letter code, e.g., US).

Run the above command in your terminal. The keystore will be generated in the `src/main/resources` folder.

---

### Step 2: Build the Project

Use Maven to build the project:

```bash
mvn clean install
```

### Step 3: Run the Application

Run the application using Maven:

```bash
mvn spring-boot:run
```

The server will start at `http://localhost:8080`.

---

## Testing the Token Endpoint

Use the following **cURL** command to request a token using the **Client Credentials** grant type:

```bash
curl -X POST \
  -u client-id:client-secret \
  -d 'grant_type=client_credentials&scope=read write' \
  -k \
  https://localhost:8443/oauth2/token
```

#### Parameters:
- `-X POST`: Specifies the HTTP method.
- `-u client-id:client-secret`: Adds HTTP Basic Authentication with your client credentials.
- `-d 'grant_type=client_credentials&scope=read write'`: Specifies the grant type and scopes.
- `-k`: Allows insecure SSL connections (useful for self-signed certificates).

### Expected Response

```json
{
  "access_token": "<jwt-token>",
  "scope": "read write",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

---

## Stopping Processes on Port 8443 (macOS)

To terminate any process using port 8443 on macOS, use the following command:

```bash
kill -9 $(lsof -t -i :8443)
```

#### Explanation:
- `lsof -t -i :8443`: Finds the Process ID (PID) using port 8443.
- `kill -9`: Forces the process to terminate.

### Verify the Process is Killed:

```bash
lsof -n -i4TCP:8443
```

---

This setup guide provides the necessary steps to configure, build, and run an OAuth2 Authorization Server using Spring Boot. Modify as needed to suit your project requirements.