Sure! Here’s the command that will generate the keystore file `keystore.p12` without asking for any interactive input. The key is to supply all the required parameters (like passwords and details) inline using the `-dname` and `-storepass` options.

Here’s the full command:

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

---

### **Explanation:**

- `-alias keyserver`: Alias for the key entry.
- `-keyalg RSA`: Use RSA algorithm for the key.
- `-keysize 2048`: Key size of 2048 bits.
- `-storetype PKCS12`: Keystore type.
- `-keystore src/main/resources/keystore.p12`: Path to the keystore.
- `-storepass password`: Password for the keystore (you can change it).
- `-keypass password`: Password for the private key (same as the keystore password, but can be different if desired).
- `-validity 3650`: Certificate validity (10 years).
- `-dname`: Distinguished name for the certificate:
    - `CN`: Common Name (e.g., localhost).
    - `OU`: Organizational Unit.
    - `O`: Organization.
    - `L`: Location (City).
    - `ST`: State.
    - `C`: Country (2-letter code, e.g., US).

Run the above command in your terminal, and the keystore will be generated in the `src/main/resources` folder without any interactive prompts.

---

### **Verifying the Configuration**

**Clean and Rebuild the Project**, Ensure that your project is clean and rebuilt to incorporate all changes:

```bash
mvn clean install
```

**Run the Application**, Start your Spring Boot application:

```bash
mvn spring-boot:run
```

**c. Testing the OAuth2 Token Endpoint**, Valid Request with Client Credentials**

Use the following `curl` command to request a token:

```bash
curl -X POST \
  -u client-id:client-secret \
  -d 'grant_type=client_credentials&scope=read write' \
  -k \
  https://localhost:8443/oauth2/token
```

- **Parameters:**
  - **`-X POST`**: Specifies the HTTP method.
  - **`-u client-id:client-secret`**: Adds HTTP Basic Authentication with your client credentials.
  - **`-d 'grant_type=client_credentials&scope=read write'`**: Sends form data specifying the grant type and scopes.
  - **`-k`**: Allows insecure SSL connections (useful for self-signed certificates).

- **Expected Response:**

  ```json
  {
    "access_token": "<jwt-token>",
    "token_type": "Bearer",
    "expires_in": 3600,
    "scope": "read write"
  }
  ```

---

#### To **kill the process using port 8080** on macOS with **one command**, you can use the following:
  ```bash
  kill -9 $(lsof -t -i :8443)
  ```

#### **Explanation:**
- **`lsof -t -i :8080`**: Finds the **Process ID (PID)** using port 8080.
- **`kill -9`**: Forces the process to terminate.

#### **Verify the Process is Killed:**
   ```bash
   lsof -n -i4TCP:8443
   ```
