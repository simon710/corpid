# CorpID Java Helper + Login Demo

This workspace contains:

- `corpid-helper`: Java helper library for CorpID/iAM login flow.
- `corpid-login-demo`: Java demo project that uses `corpid-helper` to run login.

## Implemented Based On

- `doc/DPO-CorpID-API Specification_v1.0.4(Clean).pdf`

Main points followed:

- HMAC-SHA256 signature format from common parameters.
- CEK workflow (`/api/v1/security/getKey`) and AES-GCM body encryption format.
- Login entry uses iAM Smart QR flow (`/api/v1/auth/getQR`) with `scope` + `cScope`.
- CorpID token API (`/api/eservice/v1/auth/getToken`) with callback `code` + `cAuthCode`.
- CorpID `EXT-001 /api/eservice/v1/auth/getQR` is for anonymous request flow and is not used as normal login entry.

## Project Structure

- `pom.xml`: Maven multi-module root.
- `corpid-helper/`: helper library.
- `corpid-login-demo/`: demo app.

## Required Environment Variables

Set these before running demo:

- `CORPID_CLIENT_ID` (required)
- `CORPID_CLIENT_SECRET` (required)
- `CORPID_DOMAIN` (required, e.g. `https://<CorpID_domain>`)
- `IAM_CLIENT_ID` (required)
- `IAM_CLIENT_SECRET` (required)

Optional:

- `IAM_DOMAIN` (default = `apigw-isit.staging-eid.gov.hk`)
- `KEK_P12_PATH` (default = `doc/account-centre-kek.p12`)
- `KEK_P12_PASSWORD` (default = `8568185550716550` from developer guide)
- `CALLBACK_PORT` (default = `3000`)
- `CALLBACK_PATH` (default = `/iAMSmart/LoginCallback`)
- `DIRECT_LOGIN_CALLBACK_PATH` (default = `/iAMSmart/DirectLoginCallback`)
- `CALLBACK_PUBLIC_BASE_URL` (default empty; set this to your iAM whitelist URL base, e.g. `https://localhost:7086`)
- `SERVER_SCHEME` (`http` or `https`, default `http`)
- `TLS_KEYSTORE_PATH` (default = `KEK_P12_PATH`)
- `TLS_KEYSTORE_PASSWORD` (default = `KEK_P12_PASSWORD`)
- `TLS_KEY_PASSWORD` (default = `TLS_KEYSTORE_PASSWORD`)
- `LOGIN_SOURCE` (default = `PC_Browser`)
- `LOGIN_SOURCE_SAME_DEVICE` (default = `AUTO`, will map by browser User-Agent to Android/iOS source)
- `LOGIN_SOURCE_DIFFERENT_DEVICE` (default = `LOGIN_SOURCE`)
- `LOGIN_SOURCE_IN_APP_BROWSER` (default = `AUTO`, map by User-Agent to `Android_IMS_InAppBrowser`/`iOS_IMS_InAppBrowser`)
- `LOGIN_SOURCE_DIRECT_LOGIN` (default = `AUTO`, map by User-Agent to `App_Package`/`App_Link`)
- `LOGIN_SCOPE` (default = `eidapi_auth eidapi_sign eidapi_profiles`)
- `LOGIN_C_SCOPE` (default = `corpidapi_auth`)
- `LOGIN_BROKER_PAGE` (default = `true`)
- `LOGIN_DIRECT_BROKER_PAGE` (default = `false`)
- `DIRECT_LOGIN_CODE_VERIFIER` (required when using `directLogin` mode)
- `LOGIN_FIXED_STATE` (optional; if set, use this exact `state` in getQR URL)

Notes:

- `directLogin` uses `DIRECT_LOGIN_CALLBACK_PATH` so that callback endpoint is separated from normal login callback.

If you get `D20008 Invalid online service URL`, set `CALLBACK_PUBLIC_BASE_URL` to a callback domain that is registered in iAM Smart ESP whitelist. Localhost callback URLs are usually not accepted by iAM for browser flow.

## Build

```bash
mvn -q -DskipTests package
```

## Run Login Demo (HTML + Progress)

```bash
mvn -q -f corpid-login-demo/pom.xml exec:java
```

Then open:

- `http://localhost:8088/`

Flow in the HTML page:

1. Click **Login with iAM Smart + CorpID** button.
2. Browser redirects to iAM/CorpID auth page.
3. After callback, page shows step progress.
4. Backend project uses `corpid-helper` library to exchange:
   - iAM `code` -> iAM token
   - CorpID `cCode` -> CorpID token
5. Final token summary is shown on the same HTML page.

### Run with `https://localhost:3000`

PowerShell example:

```powershell
$env:SERVER_SCHEME="https"
$env:CALLBACK_PORT="3000"
$env:CALLBACK_PUBLIC_BASE_URL="https://localhost:3000"
$env:TLS_KEYSTORE_PATH="doc/account-centre-kek.p12"
$env:TLS_KEYSTORE_PASSWORD="8568185550716550"
$env:TLS_KEY_PASSWORD="8568185550716550"
mvn -q -f corpid-login-demo/pom.xml exec:java
```
