# Yet Another Android Security Checklist

A list of checks with tips for analyzing the security of Android applications

Based on [OWASP MASVS](https://mobile-security.gitbook.io/masvs/) and [OWASP MSTG](https://mobile-security.gitbook.io/mobile-security-testing-guide/)

## L1 security verification level

Starting with open AndroidManifest.xml. 

For fast and easy analizing you can use [MobSF](Mobile-Security-Framework-MobSF).

### CODE QUALITY

#### Backupping && debugging (MSTG-STORAGE-8, MSTG‑CODE‑2)

- Allow backup (+ fullBackupContent)
- Allow debug

#### Static secrets (MSTG‑CRYPTO‑1)

- AndroidManifest.xml
- res/values/strings.xml
- local.properties or gradle.properties
-  res/assets/*

#### Testing Logs for Sensitive Data (MSTG-STORAGE-3, MSTG‑CODE‑4)

- Dynamic Ananlysis (`adb logcat`)
- Static Ananlysis (`android.util.Log`,`Log.`,`Logger`,`System.out.print`,`System.error.print`,`logfile`,`logging`,`logs`)

### NETWORKS

#### Unsafe Traffic (MSTG‑NETWORK‑1)

- HTTP
- Websockets
- Raw TCP (WireShark)

#### The app verifies the X.509 certificate and work only with certificates signed by a trusted CA (MSTG‑NETWORK‑3)

- Check with porxying SSL traffic throug BurpProxy 

#### The TLS settings are in line with current best practices (MSTG‑NETWORK‑2)

- Go to https://ssllabs.com/ssltest/analyze.html and check SSL configuration of server.

#### Determining Whether Sensitive Data is Sent to Third Parties (MSTG-STORAGE-4)

- Check that tracker services, monitor user behavior, sell banner advertisements, improve the user experience, and more do not send sesitive data to third parties.

### STORAGE

#### Checking for Sensitive Data Disclosure Through the User Interface (MSTG-STORAGE-7)

- Looking for showed on app screen `passwords`, `PAN`, `credentials`, etc...

#### Storage of PII (Personal Identifying Information) and sensetive information (MSTG-STORAGE-1 and MSTG-STORAGE-2)

- Shared Preferences
- SQLite Databases
- Realm Databases
- Internal Storage
- External Storage
- CacheDir
- Firebase Real-time Databases (`https://\<firebaseProjectName\>.firebaseio.com/.json`)

#### Check permission of the files (MSTG-STORAGE-2)

- Check the permissions of the files in `/data/data/<package-name>`.

#### Misc development info in app (MSTG‑ARCH‑1)

- Identify development files, backup files, and old files that shouldn't be included with a production release.

### Input validation and IPC

#### Testing Local Storage for Input Validation (MSTG-PLATFORM-2)

- Can another process read or change internal storage data of app with sending malicious data to input (Through user input for example (PTRAV/SQLI/COMMAND INJ/etc...) / Through IPC Mechanisms)

#### Whether Sensitive Stored Data Has Been Exposed via IPC Mechanisms (MSTG-STORAGE-6)

- AndroidManifest.xml
	- Providers
	- Services
	- Activities
	- Receivers

**!** Look at `android:exported=true`, `intent-filters`, `android:permission`, `android:protectionLevel=signature`

- Static Analysis:
	- `android.content.ContentProvider`
	- `android.database.Cursor`
	- `android.database.sqlite`
	- `.query`
	- `.update`
	- `.delete`

- Dynamic Analysis:
	- Use `adb` for trigger IPC mech-s
	- Drozer for check attack surface and IPC entrypoints

### CRYPTO

#### Testing Key Management and Implementation of crypto primitives (MSTG-STORAGE-1, MSTG-CRYPTO-1 - 5)

-Looking for keys and secrets in Storages and resources
	- AndroidManifest.xml
	- res/values/strings.xml
	- local.properties or gradle.properties
	- res/assets/*
	- Android Storages

- Looking for Private Keys in Storages and code
	- Key
	- PrivateKey
	- PublicKey
	- SecretKey
	- KeyInfo


- Сheck cryptographic methods and algorithms
	- java.security.*
	- javax.crypto.*
	- android.security.*
	- org.bouncycastle.*
	- org.spongycastle.*
	- crypto
	- Cipher
	- Mac
	- MessageDigest
	- Signature
	- Security

#### Testing Random Number Generation (MSTG-CRYPTO-6)

Insecure classes:
	- java.util.Random (PRGN can produce predictable numbers if the generator is known and the seed can be guessed.)
	- is no longer support SHA1PRNG


#### Using Third Party Secure storing libraries (MSTG-STORAGE-1, MSTG‑CRYPTO‑1 - 4)

- Java AES Crypto - A simple Android class for encrypting and decrypting strings.
- SQL Cipher - SQLCipher is an open source extension to SQLite that provides transparent 256-bit AES encryption of database files.
- Secure Preferences - Android Shared preference wrapper than encrypts the keys and values of Shared Preferences. (Check what is a secret password/key for generetion key / Check where storing a key for decrypt SP(It can get into backup data))

### LOCAL AUTHENTICATION AND SESSION MANAGEMENT

#### Testing Confirm Credentials (MSTG-AUTH-1 and MSTG-STORAGE-11)

The easiest way to check it is to do it dynamically.

	- Does the application have its own authentication mechanism? 
	- Does th application check access using the existing password or biometric authentication mechanism?
	- Is it possible to get access to the application interface on the device without screen lock mechanism?

**!** If the application doesn't have its own authentication mechanism it should check that device have screen lock mechanism with a password or biometric key.

You can also search for classes used for local authentication:
	- KeyguardManager - check that lock screen have password.
	- biometricManager - for biometric authentication.
	- BiometricPrompt - for dialog with user.


#### Session management (MSTG‑AUTH‑2 - 5)

- If stateful session management is used, the remote endpoint uses randomly generated session identifiers to authenticate client requests without sending the user's credentials. (Just check entropy of session tokens) (MSTG‑AUTH‑2)

- If stateless token-based authentication is used, the server provides a token that has been signed using a secure algorithm. (Check JWT Security: `none`-algorithm / brute-force secret key / RS256 changing on HS256 with public key signing) (MSTG‑AUTH‑3)

- The remote endpoint terminates the existing session when the user logs out. (MSTG‑AUTH‑4)

- A password policy exists and is enforced at the remote endpoint. (MSTG‑AUTH‑5)

- The remote endpoint implements a mechanism to protect against the submission of credentials an excessive number of times. (MSTG‑AUTH‑6)

- Sessions are invalidated at the remote endpoint after a predefined period of inactivity and access tokens expire. (MSTG‑AUTH‑7)


## L2 security verification level

<!-- If you despaired or just "L2 security verification level" -->

#### Determining Whether the Keyboard Cache Is Disabled for Text Input Fields (MSTG-STORAGE-5)

- Dynamic Analysis
- Static Analysis (In the layout definition TextViews attributes: android:inputType=textNoSuggestions)

#### Testing Backups for Sensitive Data (MSTG-STORAGE-8)

- `adb backup -f backup.ab -apk ru.example.app` and see what is in backup

#### Finding Sensitive Information in Auto-Generated Screenshots (MSTG-STORAGE-9)

- Just open some sesetive information in app screen and exit to louncher.

#### Checking Memory for Sensitive Data (MSTG-STORAGE-10)

- Is /*identify sensitive information*/ or /*credentials*/ stored in memory too long.

### AUTHENTICATION AND SESSION MANAGMENT

#### Testing the Device-Access-Security Policy (MSTG-SDjTORAGE-11)

Apps that process or query sensitive information should run in a trusted and secure environment. 

- PIN- or password-protected device locking
- Recent Android OS version
- USB Debugging activation
- Device encryption
- Device rooting (see also "Testing Root Detection")

#### Testing Biometric Authentication (MSTG-AUTH-8)

Biometric authentication, if any, is not event-bound (i.e. using an API that simply returns "true" or "false"). Instead, it is based on unlocking the keychain/keystore.

For example: 
```
public void authenticationSucceeded(FingerprintManager.AuthenticationResult result) {
    cipher = result.getCryptoObject().getCipher();

    //(... do something with the authenticated cipher object ...)
}
```

If app does not use cipher object and simply checks its appearance, this is called "event-bound authentication".


#### A second factor of authentication (MSTG‑AUTH‑9)

A second factor of authentication exists at the remote endpoint and the 2FA requirement is consistently enforced.

#### Sensitive transactions (MSTG‑AUTH‑10)

Sensitive transactions require step-up authentication.

#### Monitoring and logging for user (MSTG‑AUTH‑11)

The app informs the user of all sensitive activities with their account. Users are able to view a list of devices, view contextual information (IP address, location, etc.), and to block specific devices.

### Network Communication Requirements


#### Custom Certificate Stores and Certificate Pinning (MSTG‑NETWORK‑4)

The app either uses its own certificate store, or pins the endpoint certificate or public key, and subsequently does not establish connections with endpoints that offer a different certificate or key, even if signed by a trusted CA.

#### Insecure communication for critical operations (MSTG‑NETWORK‑5)

The app doesn't rely on a single insecure communication channel (email or SMS) for critical operations, such as enrollments and account recovery.

#### Security Provider (MSTG‑NETWORK‑6)

The app only depends on up-to-date connectivity and security libraries.

