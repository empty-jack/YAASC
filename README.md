# Yet Another Android Security Checklist
A list of checks with tips for analyzing the security of Android applications

## Backupping && debugging (MSTG-STORAGE-8)

- Allow backup (+ fullBackupContent)
- Allow debug

## Static secrets (MSTG‑CRYPTO‑1)

- AndroidManifest.xml
- res/values/strings.xml
- local.properties or gradle.properties

## Testing Logs for Sensitive Data (MSTG-STORAGE-3)

- Dynamic Ananlysis (`adb logcat`)
- Static Ananlysis (`android.util.Log`,`Log.`,`Logger`,`System.out.print`,`System.error.print`,`logfile`,`logging`,`logs`)

## Unsafe Traffic (MSTG‑NETWORK‑1)

- HTTP
- Websockets
- Raw TCP (WireShark)

## The app verifies the X.509 certificate and work only with certificates signed by a trusted CA (MSTG‑NETWORK‑3)

- Check with porxying SSL traffic throug BurpProxy 

## The TLS settings are in line with current best practices (MSTG‑NETWORK‑2)

- Go to https://ssllabs.com/ssltest/analyze.html and check SSL configuration of server.

## Determining Whether Sensitive Data is Sent to Third Parties (MSTG-STORAGE-4)

- Check that tracker services, monitor user behavior, sell banner advertisements, improve the user experience, and more do not send sesitive data to third parties.

## Storage of PII (Personal Identifying Information) and sensetive information (MSTG-STORAGE-1 and MSTG-STORAGE-2)

- Shared Preferences
- SQLite Databases
- Realm Databases
- Internal Storage
- External Storage
- CacheDir
- Firebase Real-time Databases (`https://\<firebaseProjectName\>.firebaseio.com/.json`)

## Check permission of the files (MSTG-STORAGE-2)

- Check the permissions of the files in `/data/data/<package-name>`.

## Using Third Party Secure storing libraries (MSTG-STORAGE-1)

- Java AES Crypto - A simple Android class for encrypting and decrypting strings.
- SQL Cipher - SQLCipher is an open source extension to SQLite that provides transparent 256-bit AES encryption of database files.
- Secure Preferences - Android Shared preference wrapper than encrypts the keys and values of Shared Preferences. (Check what is a secret password/key for generetion key / Check where storing a key for decrypt SP(It can get into backup data))

## Misc development info in app (MSTG‑ARCH‑1)

- Identify development files, backup files, and old files that shouldn't be included with a production release.

## Testing Local Storage for Input Validation (MSTG-PLATFORM-2)

- Can another process read or change internal storage data of app with sending malicious data to input (Through user input for example (PTRAV/SQLI/COMMAND INJ/etc...) / Through IPC Mechanisms)

## Whether Sensitive Stored Data Has Been Exposed via IPC Mechanisms (MSTG-STORAGE-6)

- AndroidManifest.xml
	- Providers
	- Services
	- Activities
	- Receivers

! Look at `android:exported=true`, `intent-filters`, `android:permission`, `android:protectionLevel=signature`

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

## Checking for Sensitive Data Disclosure Through the User Interface (MSTG-STORAGE-7)

- Looking for showed on app screen `passwords`, `PAN`, `credentials`, etc...

<!-- If you despaired or just "L2 security verification level" -->

## Determining Whether the Keyboard Cache Is Disabled for Text Input Fields (MSTG-STORAGE-5)

- Dynamic Analysis
- Static Analysis (In the layout definition TextViews attributes: android:inputType=textNoSuggestions)

## Testing Backups for Sensitive Data (MSTG-STORAGE-8)

- `adb backup -f backup.ab -apk ru.example.app` and see what is in backup

## Finding Sensitive Information in Auto-Generated Screenshots (MSTG-STORAGE-9)

- Just open some sesetive information in app screen and exit to louncher.

## Checking Memory for Sensitive Data (MSTG-STORAGE-10)

- Is /*identify sensitive information*/ or /*credentials*/ stored in memory too long.

## Testing the Device-Access-Security Policy (MSTG-STORAGE-11)
