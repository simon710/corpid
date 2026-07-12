@echo off
setlocal EnableExtensions EnableDelayedExpansion

cd /d "%~dp0"

echo [1/3] Loading .env ...
if not exist ".env" (
  echo ERROR: .env not found in %CD%
  exit /b 1
)

for /f "usebackq tokens=* delims=" %%L in (".env") do (
  set "line=%%L"
  if defined line (
    if not "!line:~0,1!"=="#" (
      for /f "tokens=1* delims==" %%A in ("!line!") do (
        set "k=%%A"
        set "v=%%B"
        if defined k set "!k!=!v!"
      )
    )
  )
)

echo [2/3] Releasing target port if occupied ...
set "PORT_TO_FREE=%CALLBACK_PORT%"
if not defined PORT_TO_FREE set "PORT_TO_FREE=5173"
echo Target port: %PORT_TO_FREE%
powershell -NoProfile -ExecutionPolicy Bypass -Command "$ports=@(); $ports += [int]%PORT_TO_FREE%; $publicBase='%CALLBACK_PUBLIC_BASE_URL%'; if($publicBase){ try{ $uri=[Uri]$publicBase; if($uri.Port -gt 0 -and -not ($ports -contains $uri.Port)){ $ports += $uri.Port } } catch {} }; foreach($port in $ports){ Write-Host ('Checking port ' + $port); $c=Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue; if($c){ $procIds=@($c | Select-Object -ExpandProperty OwningProcess -Unique); foreach($procId in $procIds){ Write-Host ('Killing PID ' + $procId + ' on port ' + $port); Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue } } else { Write-Host ('No listener found on port ' + $port + '.') } }"

echo [3/4] Building helper module ...
call mvn -q -pl corpid-helper -am -DskipTests install
if errorlevel 1 (
  echo ERROR: Failed to build helper module.
  exit /b 1
)

echo [4/4] Building demo module (refresh web resources) and starting server ...
echo SERVER_SCHEME=%SERVER_SCHEME%
echo CALLBACK_PORT=%CALLBACK_PORT%

REM -am builds corpid-helper dependency; compile copies src/main/resources/web/login.html
REM into target/classes so the served page reflects the latest HTML changes.
mvn -e -X -pl corpid-login-demo -am compile exec:java
set "rc=%ERRORLEVEL%"

echo.
echo Finished with exit code %rc%
exit /b %rc%
