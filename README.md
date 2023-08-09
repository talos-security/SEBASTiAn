# SEBASTiAn

> a **S**tatic and **E**xtensible **B**lack-box **A**pplication **S**ecurity **T**esting tool for **i**OS and **An**droid applications

<!--[![Build Status](https://github.com/talos-security/SEBASTiAn/workflows/Build/badge.svg)](https://github.com/talos-security/SEBASTiAn/actions?query=workflow%3ABuild)-->

**SEBASTiAn**: a **S**tatic and **E**xtensible **B**lack-box **A**pplication **S**ecurity **T**esting tool for **i**OS and **An**droid applications is a platform agnostic and easily extensible modular tool for performing static security assessments of mobile applications.
It can analyze Android (`apk`) and iOS (`ipa`) applications by providing a unified JSON report containing details about the identified vulnerabilities, remediation suggestions, web resources for further insights, and the location where the vulnerable code/configuration was found.

## ❱ Publication

More details about **SEBASTiAn** can be found in the paper [SEBASTiAn: a Static and Extensible Black-box Application Security Testing tool for iOS and Android applications](https://doi.org/10.36227/techrxiv.21261573.v1):

```BibTex
@article{PAGANO2023101448,
  title = {SEBASTiAn: A static and extensible black-box application security testing tool for iOS and Android applications},
  journal = {SoftwareX},
  volume = {23},
  pages = {101448},
  year = {2023},
  issn = {2352-7110},
  doi = {https://doi.org/10.1016/j.softx.2023.101448},
  url = {https://www.sciencedirect.com/science/article/pii/S2352711023001449},
  author = {Francesco Pagano and Andrea Romdhana and Davide Caputo and Luca Verderame and Alessio Merlo}
}
```

## ❱ Installation

The only requirement of this project is a working `Python 3` installation (along with
its package manager `pip`). Depending on your operating system, you might need a
different version of Python, as specified in the table below:

| Python version     | Ubuntu                   | Windows                  | MacOS                    |
|:------------------:|:------------------------:|:------------------------:|:------------------------:|
| **2.x**            | :trollface:              | :trollface:              | :trollface:              |
| **3.6** or lower   | :heavy_multiplication_x: | :heavy_multiplication_x: | :heavy_multiplication_x: |
| **3.7**            | :heavy_check_mark:       | :warning:                | :heavy_check_mark:       |
| **3.8**            | :heavy_check_mark:       | :heavy_check_mark:       | :heavy_check_mark:       |
| **3.9** or greater | :heavy_check_mark:       | :heavy_check_mark:       | :heavy_check_mark:       |

:warning: might work by installing `lief` package manually, since there is no stable prebuilt
wheels are currently available.

Run the following commands in the main directory of the project (`SEBEASTiAn/`) to install the needed dependencies:

```Shell
# Make sure to run the commands in SEBASTiAn/ directory.

# Using a virtual environment is highly recommended, e.g., virtualenv.
# If not using virtualenv (https://virtualenv.pypa.io/), skip the next two lines.
virtualenv -p python3 venv
source venv/bin/activate

# Install SEBASTiAn's requirements.
python3 -m pip install -r src/requirements.txt
```

After the requirements are installed, make a quick test to check that everything works
correctly:

```Shell
$ cd src/
$ # The following command has to be always executed from SEBASTiAn/src/ directory
$ # or by adding SEBASTiAn/src/ directory to PYTHONPATH environment variable.
$ python3 -m cli --help
usage: python3 -m cli [-h] [-l {en,it}] [-i] [--fail-fast] [-t TIMEOUT]
...
```

SEBASTiAn is ready to be used; see the help message for more information.

## ❱ Usage

From now on, SEBASTiAn will be considered as an executable available as `SEBASTiAn`, so you need to adapt the commands according to how you install the tool:

* **Docker image**: a local directory containing the application to analyze has to be
mounted to `/workdir` in the container (e.g., the current directory `"${PWD}"`), so the
command:

    ```Shell
    SEBASTiAn [params...]
    ```

    becomes:

    ```Shell
    docker run --rm -it -u $(id -u):$(id -g) -v "${PWD}":"/workdir" SEBASTiAn [params...]
    ```
    
    Alternatively, you can directly run SEBASTiAn from its official docker image, available on Docker Hub:

    ```Shell
    docker run --rm -it -u $(id -u):$(id -g) -v "${PWD}":"/workdir" talossec/sebastian:latest [params...]

* **From source**: every instruction has to be executed from the `SEBASTiAn/src/`
directory (or by adding `SEBASTiAn/src/` directory to `PYTHONPATH` environment
variable) and the command:

    ```Shell
    SEBASTiAn [params...]
    ```

    becomes:

    ```Shell
    python3 -m SEBASTiAn.cli [params...]
    ```

Let's start by looking at the help message:

```Shell

$ SEBASTiAn --help
SEBASTiAn [-h] [-l {en,it}] [-i] [--fail-fast] [-t TIMEOUT] [--keep-files] <FILE>
```

There is only one mandatory parameter: `<FILE>`, the path (relative or absolute) to
the apk file to analyze.

* `-l {en,it}, --language {en,it}`, The language used for the vulnerabilities. Allowed values are: en, it.

* `-i, --ignore-libs`, Ignore known third-party libraries during the vulnerability analysis (only for Android).

* `--fail-fast`, Make the entire analysis fail on the first failed vulnerability check.
  
* `-t TIMEOUT, --timeout TIMEOUT` Make the analysis fail if it takes longer than the timeout (in seconds). By default, a timeout of 1200 seconds (20 minutes) is used.

* `--keep-files`, Keep intermediate files generated during the analysis (only for iOS).

## ❱ Vulnerabilities

The vulnerabilities checked in SEBASTiAn are divided into two macro-categories: **[Android Vulnerabilities](#-android-vulnerabilities)** and **[iOS Vulnerabilities](#-ios-vulnerabilities)**.

### ❱ Android Vulnerabilities

### [access_device_id](https://github.com/talos-security/SEBASTiAn/tree/master/src/SEBASTiAn/android_vulnerabilities/access_device_id)

> This Plugin checks if the app gets the device ID (IMEI) to identify the specific device. This approach has three significant drawbacks: I) it is unusable on non-phone devices, II) it persists across device data wipes, and III) it needs a special privilege to be executed.

### [access_internet_without_permission](https://github.com/talos-security/SEBASTiAn/tree/master/src/SEBASTiAn/android_vulnerabilities/access_internet_without_permission)

> This app contains code for Internet access but does not have the Internet permission in AndroidManifest.xml. This may be caused by an app misconfiguration or a malicious app that tries to access the network interface without proper permission.

### [access_mock_location](https://github.com/talos-security/SEBASTiAn/tree/master/src/SEBASTiAn/android_vulnerabilities/access_mock_location)

> The Plugin checks for the presence of the permission Access Mock Location in the Android Manifest. This permission only works in emulated environments, and it is deprecated.

### [allow_all_hostname](https://github.com/talos-security/SEBASTiAn/tree/master/src/SEBASTiAn/android_vulnerabilities/allow_all_hostname)

> This Plugin verifies whether the app validates the Common Name in the SSL certificate. This critical vulnerability allows attackers to implement MitM attacks with their valid certificates. It is a violation of OWASP Mobile TOP 10 Security Risks.

### [backup_enabled](https://github.com/talos-security/SEBASTiAn/tree/master/src/SEBASTiAn/android_vulnerabilities/backup_enabled)

> This Plugin checks whether the ADB Backup is enabled for the app. If this is the case, attackers with physical access to the device can copy all of the sensitive data of the app included in the backup.

### [base64_string](https://github.com/talos-security/SEBASTiAn/tree/master/src/SEBASTiAn/android_vulnerabilities/base64_string)

> This Plugin checks the presence of base64 encoded strings, notifying the developer.

### [check_calling_or_self_permission](https://github.com/talos-security/SEBASTiAn/blob/master/src/SEBASTiAn/android_vulnerabilities/check_calling_or_self_permission)

> A component that uses run-time permission checking via checkCallingOrSelfPermission for access control grants permission to all components if it grants permission even once to a component that is in the same app as that itself. Suppose checkCallingOrSelfPermission is used to protect a component that performs a sensitive operation. In that case, a component in a malicious app can escalate its privilege and access the component.

### [check_permission](https://github.com/talos-security/SEBASTiAn/blob/master/src/SEBASTiAn/android_vulnerabilities/check_permission)

> A component that uses checkPermission to verify access control at run-time must obtain the PID and UID of the calling component before calling checkPermission. The Binder API provides methods getCallingPID() and getCallingUID() to determine the calling component's PID and UID, respectively. However, these methods do not always return the calling PID and UID. When an application is started, the system creates a thread of execution called main. The system does not create a separate thread for each component instance. All components that run in the same process are instantiated in the main thread, and system calls to each component are dispatched from that thread. If Binder.getCallingPID() and Binder.getCallingPID() are called from the main thread, they do not return the PID and UID of the process in which the calling component is running. Instead, they return the PID and UID of the process in which the protected component is running. In such a scenario, if the process in which the protected component is running is granted permission, checkPermission will always be true. A malicious component can exploit this vulnerability to access the protected component.

### [cordova_access_origin](https://github.com/talos-security/SEBASTiAn/blob/master/src/SEBASTiAn/android_vulnerabilities/cordova_access_origin_with_csp)

> This Plugin checks if the app properly configures the Network Request Whitelist options in its Cordova config.xml file. The Plugin also checks if the app configures the Network Request Whitelist options to accept plain HTTP URLs. The Network Request Whitelist options control which network requests are allowed.

### [cordova_allow_intent](https://github.com/talos-security/SEBASTiAn/tree/master/src/SEBASTiAn/android_vulnerabilities/cordova_allow_intent_wildcard)

> This Plugin checks if the app configures the Intent Whitelist options to accept HTTPS URLs from any domain. The Intent Whitelist options control which URLs the app is allowed to ask the system to open. This Plugin also checks if the app configures the Navigation Whitelist options to accept HTTPS connections from any domain.

### [cordova_allow_navigation](https://github.com/talos-security/SEBASTiAn/tree/master/src/SEBASTiAn/android_vulnerabilities/cordova_allow_navigation_wildcard)

> This Plugin checks whether the Navigation Whitelist accepts HTTPS connections from any domain. Moreover, the Plugin checks if the app does not properly configure the Navigation Whitelist options in its Cordova config.xml file.

### [crypto_constant_iv](https://github.com/talos-security/SEBASTiAn/tree/master/src/SEBASTiAn/android_vulnerabilities/crypto_constant_iv)

> This Plugin verifies if the initialization vector (IV) is not random. Consequently, encrypting a particular piece of information with a symmetric key will yield the same result every time encryption is applied to that information with the same symmetric key.

### [crypto_constant_key](https://github.com/talos-security/SEBASTiAn/tree/master/src/SEBASTiAn/android_vulnerabilities/crypto_constant_key)

> This Plugin checks if the app stores encryption keys in the source code. The apps that present this vulnerability are vulnerable to forgery attacks and information leaks.

### [crypto_constant_salt](https://github.com/talos-security/SEBASTiAn/tree/master/src/SEBASTiAn/android_vulnerabilities/crypto_constant_salt)

> This Plugin checks if the app uses a constant salt.

### [crypto_ecb_cipher](https://github.com/talos-security/SEBASTiAn/tree/master/src/SEBASTiAn/android_vulnerabilities/crypto_ecb_cipher)

> This Plugin checks if the app uses Block Cipher algorithms in ECB mode for encrypting sensitive information. Block Cipher algorithms in ECB mode are known to be vulnerable.

### [crypto_keystore_entry_without_password](https://github.com/talos-security/SEBASTiAn/tree/master/src/SEBASTiAn/android_vulnerabilities/crypto_keystore_entry_without_password)

> This Plugin checks if an app stores encryption keys without any protection parameter in a Keystore accessible by other apps. Apps that present this behavior are vulnerable to information exposure. Keystore provides `setEntry` API to store a key entry. Along with the alias and the key, `setEntry` API takes an instance of ProtectionParameter as an argument to protect the entry contents.

### [crypto_small_iteration_count](https://github.com/talos-security/SEBASTiAn/tree/master/src/SEBASTiAn/android_vulnerabilities/crypto_small_iteration_count)

> The Plugin checks if the app passes an iteration count smaller than 1000. If so, the `PBEParameterSpec` and the `PBEKeySpec` constructors are insecure.

### [debuggable_application](https://github.com/talos-security/SEBASTiAn/tree/master/src/SEBASTiAn/android_vulnerabilities/debuggable_application)

> The Plugin checks if the DEBUG mode is on inside the app. Debug mode is discouraged in production since malicious users can debug the app and sniff verbose error information through Logcat.

### [default_scheme_http](https://github.com/talos-security/SEBASTiAn/tree/master/src/SEBASTiAn/android_vulnerabilities/default_scheme_http)

> This Plugin checks if the app uses `HttpHost`, but its default scheme is `HTTP`.

### [dynamic_code_loading](https://github.com/talos-security/SEBASTiAn/tree/master/src/SEBASTiAn/android_vulnerabilities/dynamic_code_loading)

> This Plugin checks if the app contains code that dynamically loads classes from `.jar` files.

### [empty_permission_group](https://github.com/talos-security/SEBASTiAn/tree/master/src/SEBASTiAn/android_vulnerabilities/empty_permission_group)

> This Plugin searches for a user-defined empty `permissionGroup` in the Android Manifest. Setting the `permissionGroup` attribute to an empty value will invalidate the permission definition, and no other application can use the permission.

### [enforce_calling_or_self_permission](https://github.com/talos-security/SEBASTiAn/blob/master/src/SEBASTiAn/android_vulnerabilities/enforce_calling_or_self_permission/details_en.json)

> A component that uses run-time permission checking via enforceCallingOrSelfPermission for access control grants permission to all components if it grants permission even once to a component that is in the same app as that itself. If enforceCallingOrSelfPermission is used to protect a component that performs a sensitive operation, then a component in a malicious app can escalate its privilege and access the component.

### [enforce_permission](https://github.com/talos-security/SEBASTiAn/blob/master/src/SEBASTiAn/android_vulnerabilities/enforce_permission/details_en.json)

> A component that uses enforcePermission to verify access control at run-time will need to obtain the PID and UID of the calling component before calling enforcePermission. The Binder API provides methods getCallingPID() and getCallingUID() to determine the calling component's PID and UID, respectively. However, these methods do not always return the calling PID and UID. When an application is started, the system creates a thread of execution for the application called main. The system does not create a separate thread for each component instance. All components that run in the same process are instantiated in the main thread, and system calls to each component are dispatched from that thread. If Binder.getCallingPID() and Binder.getCallingPID() are called from the main thread, they do not return the PID and UID of the process in which the calling component is running. Instead, they return the PID and UID of the process in which the protected component runs. In such a scenario, if the process in which the protected component is running is granted permission, then `enforcePermission` will not throw a SecurityException. A malicious component can exploit this vulnerability to access the protected component.

### [exported_component](https://github.com/talos-security/SEBASTiAn/tree/master/src/SEBASTiAn/android_vulnerabilities/exported_component)

> This Plugin detects exported components for receiving external applications' actions. These components can be initialized by other apps and used maliciously. The Plugin also checks exported ContentProvider, allowing any other app on the device to access it (`AndroidManifest.xml`). Found exported components lacking `android:` prefix in an exported attribute.

### [external_storage](https://github.com/talos-security/SEBASTiAn/tree/master/src/SEBASTiAn/android_vulnerabilities/external_storage)

> This plugin checks if the app uses the external storage access API. Any app in the system can access external storage; thus, its use for security-critical files is discouraged.

### [idos_xas_fi](https://github.com/talos-security/SEBASTiAn/tree/master/src/SEBASTiAn/android_vulnerabilities/idos_xas_fi/details_en.json)

> Potentially unsafe uses of parameters associated with intents have been found.

### [implicit_intent_service](https://github.com/talos-security/SEBASTiAn/tree/master/src/SEBASTiAn/android_vulnerabilities/implicit_intent_service)

> This Plugin identifies implicit intents within the app that can start services. Using an implicit intent to start a service is a security hazard because of the uncertainty of what service will respond to the intent.

### [insecure_connection](https://github.com/talos-security/SEBASTiAn/tree/master/src/SEBASTiAn/android_vulnerabilities/insecure_connection)

> This Plugin checks whether the app contains URLs not under SSL. This security hazard allows the interception of all the information exchanged with those URLs.

### [insecure_hostname_verifier](https://github.com/talos-security/SEBASTiAn/tree/master/src/SEBASTiAn/android_vulnerabilities/insecure_hostname_verifier)

> The Plugin checks whether the app allows self-defined HOSTNAME VERIFIER to accept all Common Names. This critical vulnerability allows attackers to make MitM attacks with their valid certificates. It is a violation of OWASP Mobile TOP 10 Security Risks.

### [insecure_socket](https://github.com/talos-security/SEBASTiAn/tree/master/src/SEBASTiAn/android_vulnerabilities/insecure_socket)

> This Plugin checks the usage of `SSLCertificateSocketFactory.createSocket()`. The created socket can be vulnerable to Man-in-the-Middle (MitM) attacks.

### [insecure_socket_factory](https://github.com/talos-security/SEBASTiAn/tree/master/src/SEBASTiAn/android_vulnerabilities/insecure_socket_factory)

> This Plugin checks whether the app contains code that relies on instances of socket factory with all SSL security checks disabled, using an optional handshake timeout and SSL session cache. Those sockets are vulnerable to MitM attacks.

### [intent_filter_misconfiguration](https://github.com/talos-security/SEBASTiAn/tree/master/src/SEBASTiAn/android_vulnerabilities/intent_filter_misconfiguration)

> The app contains misconfiguration in the intent filter of at least one component of the `AndroidManifest.xml`. The plugin also checks if the app does not include a Content Security Policy (CSP).

### [invalid_server_certificate](https://github.com/talos-security/SEBASTiAn/tree/master/src/SEBASTiAn/android_vulnerabilities/invalid_server_certificate)

> This Plugin inspects whether the app validates the SSL Certificates. It allows self-signed, expired, or mismatched CN certificates for SSL connection. This critical vulnerability allows attackers to make MitM attacks.

### [keystore_without_password](https://github.com/talos-security/SEBASTiAn/tree/master/src/SEBASTiAn/android_vulnerabilities/keystore_without_password)

>This Plugin checks whether a password protects the Keystore. This security hazard allows malicious users with physical access to the Keystore file to access the keys and certificates.

### [obfuscation_rate](https://github.com/talos-security/SEBASTiAn/tree/master/src/SEBASTiAn/android_vulnerabilities/obfuscation_missing)

> The Plugin checks if the app is obfuscated and eventually reports its obfuscation rate.

### [permission_dangerous](https://github.com/talos-security/SEBASTiAn/tree/master/src/SEBASTiAn/android_vulnerabilities/permission_dangerous)

> This Plugin checks whether the protection level of the app's classes is *dangerous*, allowing any other app to access this permission (`AndroidManifest.xml`).

### [permission_normal](https://github.com/talos-security/SEBASTiAn/tree/master/src/SEBASTiAn/android_vulnerabilities/permission_normal)

> This Plugin checks whether at least one class declared in the Android Manifest of the app is protected with custom permissions, defined with a *normal* or *default* permission level. This allows malicious apps to register and receive messages for this app.

### [runtime_command](https://github.com/talos-security/SEBASTiAn/tree/master/src/SEBASTiAn/android_vulnerabilities/runtime_command)

> This Plugin validates if the app is using the critical function `Runtime.getRuntime().exec()`.

### [runtime_command_root](https://github.com/talos-security/SEBASTiAn/tree/master/src/SEBASTiAn/android_vulnerabilities/runtime_command_root)

> This Plugin verifies whether the app requests root permissions through the command `Runtime.getRuntime().exec("su")` or the command `Runtime.getRuntime().exec("sudo")`

### [send_sms](https://github.com/talos-security/SEBASTiAn/tree/master/src/SEBASTiAn/android_vulnerabilities/send_sms)

> This Plugin verifies if the app can send SMS messages (`sendDataMessage`, `sendMultipartTextMessage`, or `sendTextMessage`) that could be a cost for the user if maliciously exploited.

### [shared_user_id](https://github.com/talos-security/SEBASTiAn/tree/master/src/SEBASTiAn/android_vulnerabilities/shared_user_id)

> The Plugin checks if the app uses the `sharedUserId` attribute. Suppose this attribute is set to the same value for two or more applications. In that case, they will all share the same ID — provided the same certificate also signs them.

### [sqlite_exec_sql](https://github.com/talos-security/SEBASTiAn/tree/master/src/SEBASTiAn/android_vulnerabilities/sqlite_exec_sql)

> This Plugin checks for the presence of SQLite's `execSQL()` method. The `execSQL()` method could create a SQL query based on the user input content, potentially vulnerable to SQL injection attacks.

### [system_permission_usage](https://github.com/talos-security/SEBASTiAn/tree/master/src/SEBASTiAn/android_vulnerabilities/system_permission_usage)

> This Plugin checks if the app uses necessary permissions to manage filesystems and packages. The System Permission should be confined only to device manufacturers or Google system apps. If not, it may be a malicious app.

### [webview_allow_file_access](https://github.com/talos-security/SEBASTiAn/tree/master/src/SEBASTiAn/android_vulnerabilities/webview_allow_file_access)

> The Plugin checks for the presence of the `setAllowFileAccess(true)` method in a WebView.

### [webview_ignore_ssl_error](https://github.com/talos-security/SEBASTiAn/tree/master/src/SEBASTiAn/android_vulnerabilities/webview_ignore_ssl_error)

> The plugin checks if an Android app can display web pages by loading HTML/JavaScript files in a WebView.

### [webview_intercept_request](https://github.com/talos-security/SEBASTiAn/tree/master/src/SEBASTiAn/android_vulnerabilities/webview_intercept_request)

> The Plugin checks if the app loads resources (e.g., JavaScript) using a WebView, and control the resources being loaded on a webpage via the `shouldInterceptRequest` method in WebViewClient.

### [webview_javascript_enabled](https://github.com/talos-security/SEBASTiAn/tree/master/src/SEBASTiAn/android_vulnerabilities/webview_javascript_enabled)

> This Plugin checks if the app uses  `setJavaScriptEnabled(true)` in WebView. Enabling JavaScript exposes to malicious code injection that would be executed with the same permissions (XSS attacks).

### [webview_javascript_interface](https://github.com/talos-security/SEBASTiAn/tree/master/src/SEBASTiAn/android_vulnerabilities/webview_javascript_interface)

> This Plugin verifies the presence of the `addJavascriptInterface` method within the app code.

### [webview_override_url](https://github.com/talos-security/SEBASTiAn/tree/master/src/SEBASTiAn/android_vulnerabilities/webview_override_url)

> This Plugin checks whether the Android app shows web content in a WebView, and controls navigation across webpages via the `shouldOverrideUrlLoading` method in WebViewClient.

### [world_readable_writable](https://github.com/talos-security/SEBASTiAn/tree/master/src/SEBASTiAn/android_vulnerabilities/world_readable_writable)

> This Plugin checks whether the app allows file access in World Readable/Writable mode. This functionality is deprecated in API Level 17 and removed since API Level 24.

### ❱ iOS Vulnerabilities

### [allow_http_plist](https://github.com/talos-security/SEBASTiAn/tree/master/src/SEBASTiAn/ios_vulnerabilities/allow_http_plist)

> The Plugin checks if the app allows the HTTP protocol.

### [arc_flag_missing](https://github.com/talos-security/SEBASTiAn/tree/master/src/SEBASTiAn/ios_vulnerabilities/arc_flag_missing)

> The Plugin checks if the binary is compiled without the Automatic Reference Counting (ARC) flag. ARC is a compiler feature that provides automatic memory management of Objective-C objects and is an exploit mitigation mechanism against memory corruption vulnerabilities.

### [code_signature_missing](https://github.com/talos-security/SEBASTiAn/tree/master/src/SEBASTiAn/ios_vulnerabilities/code_signature_missing)

> The Plugin checks if the binary does not have a code signature.

### [encryption_missing](https://github.com/talos-security/SEBASTiAn/tree/master/src/SEBASTiAn/ios_vulnerabilities/encryption_missing)

> The Plugin checks if the binary is not encrypted.

### [insecure_api](https://github.com/talos-security/SEBASTiAn/tree/master/src/SEBASTiAn/ios_vulnerabilities/insecure_api)

> The Plugin checks if the binary uses insecure API(s).

### [insecure_connection_plist](https://github.com/talos-security/SEBASTiAn/tree/master/src/SEBASTiAn/ios_vulnerabilities/insecure_connection_plist)

> The Plugin checks if the app adds exceptions for possible insecure connections in `Info.plist` file.

### [insecure_random](https://github.com/talos-security/SEBASTiAn/tree/master/src/SEBASTiAn/ios_vulnerabilities/insecure_random)

> The Plugin checks if the binary uses some insecure random API(s).

### [insecure_tls_version_plist](https://github.com/talos-security/SEBASTiAn/tree/master/src/SEBASTiAn/ios_vulnerabilities/insecure_tls_version_plist)

> The Plugin checks if the app sets the minimum value of TLS version TLSv1.0 or TLSv1.1, which are unsafe.

### [logging_function](https://github.com/talos-security/SEBASTiAn/tree/master/src/SEBASTiAn/ios_vulnerabilities/logging_function)

> The Plugin checks if the Mach-O binary uses logging function(s).

### [malloc_function](https://github.com/talos-security/SEBASTiAn/tree/master/src/SEBASTiAn/ios_vulnerabilities/malloc_function)

> The Plugin checks if the binary may use `malloc` function.

### [no_forward_secrecy_plist](https://github.com/talos-security/SEBASTiAn/tree/master/src/SEBASTiAn/ios_vulnerabilities/no_forward_secrecy_plist)

> The Plugin checks if the app turns off the server's requirement to support Perfect Forward Secrecy (PFS) through Elliptic Curve Diffie-Hellman Ephemeral (ECDHE).

### [nx_bit_missing](https://github.com/talos-security/SEBASTiAn/tree/master/src/SEBASTiAn/ios_vulnerabilities/nx_bit_missing)

> The Plugin checks if the binary does not have the NX bit set. NX bit offers protection against exploitation of memory-corruption vulnerabilities by marking the memory page as non-executable. However, iOS never allows an app to execute from writeable memory.

### [pie_flag_missing](https://github.com/talos-security/SEBASTiAn/tree/master/src/SEBASTiAn/ios_vulnerabilities/pie_flag_missing)

> The Plugin checks if the binary is built without the Position Independent Code flag.

### [restricted_segment_missing](https://github.com/talos-security/SEBASTiAn/tree/master/src/SEBASTiAn/ios_vulnerabilities/restricted_segment_missing)

> The Plugin checks if the Mach-O binary file has no restricted segment that prevents dynamic loading of dylib for arbitrary code injection.

### [rpath_set](https://github.com/talos-security/SEBASTiAn/tree/master/src/SEBASTiAn/ios_vulnerabilities/rpath_set)

> The Plugin checks if the binary has Runpath Search Path (@rpath) set. Sometimes, an attacker can abuse this feature to run the arbitrary executable for code execution and privilege escalation.

### [stack_canary_missing](https://github.com/talos-security/SEBASTiAn/tree/master/src/SEBASTiAn/ios_vulnerabilities/stack_canary_missing)

> The Plugin checks if the binary does not have a stack canary value added. Stack canaries are used to detect and prevent exploits from overwriting return addresses.

### [symbols_stripped](https://github.com/talos-security/SEBASTiAn/tree/master/src/SEBASTiAn/ios_vulnerabilities/symbols_stripped)

> The Plugin checks if the app symbols are available.

### [weak_crypto](https://github.com/talos-security/SEBASTiAn/tree/master/src/SEBASTiAn/ios_vulnerabilities/weak_crypto)

> The Plugin checks if the binary uses some weak crypto API(s).

### [weak_hashes](https://github.com/talos-security/SEBASTiAn/tree/master/src/SEBASTiAn/ios_vulnerabilities/weak_hashes)

> The Plugin checks if the binary uses some weak hashing API(s).

### [webview_load_data_with_base_url](https://github.com/talos-security/SEBASTiAn/tree/master/src/SEBASTiAn/android_vulnerabilities/webview_load_data_with_base_url)

> An application can load a saved HTML web page as a string using loadDataWithBaseUrl() with file scheme baseURL. Since WebView has permission to access all of the app's resources, JavaScript code executing in the context of WebView will also have the same permissions. If the saved web page sources JavaScript code from a malicious server, these permissions can be abused.

## ❱ Contributing

Questions, bug reports, and pull requests are welcome on GitHub at [https://github.com/talos-security/SEBASTiAn](https://github.com/talos-security/SEBASTiAn).

## ❱ License

This tool is available under a dual license: a commercial one required for closed-source or commercial projects and an AGPL license for open-source projects.

Depending on your needs, you must choose one of them and follow its policies. The policies and agreements for each license type are detailed in the [LICENSE.COMMERCIAL](LICENSE.COMMERCIAL) and [LICENSE](LICENSE) files.

## ❱ Credits

This software was developed for research purposes in collaboration with the [Computer Security Lab (CSecLab)](https://www.csec.it/).
## ❱ Team

* [Davide Caputo](https://csec.it/people/davide_caputo/) - Cyber Security Engineer @ Talos
* [Gabriel Claudiu Georgiu](https://github.com/ClaudiuGeorgiu) - Senior Developer @ iGenius
* [Francesco Pagano](https://csec.it/people/francesco_pagano) - Research Assistant & Developer
* [Andrea Romdhana](https://csec.it/people/andrea-romdhana) - Cyber Security Engineer @ Talos
* [Luca Verderame](https://csec.it/people/luca_verderame) - Assistant Professor @ Unige & CEO @ Talos

## ❱ Star History


[![Star History Chart](https://api.star-history.com/svg?repos=talos-security/SEBASTiAn&type=Date)](https://star-history.com/#talos-security/SEBASTiAn&Date)
