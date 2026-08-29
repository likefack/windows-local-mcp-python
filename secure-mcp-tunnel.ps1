# Secure MCP Tunnel integration helpers.
#
# This file is dot-sourced by the setup and normal-startup launchers.  It keeps
# Runtime API keys in the current user's Windows Credential Manager and never
# serializes the secret into a profile, state file, command line, or log.

function Initialize-TunnelCredentialStore {
    if ($null -ne ("WindowsLocalMcp.CredentialStore" -as [type])) {
        return
    }

    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security;

namespace WindowsLocalMcp
{
    public static class CredentialStore
    {
        private const uint CRED_TYPE_GENERIC = 1;
        private const uint CRED_PERSIST_LOCAL_MACHINE = 2;
        private const int ERROR_NOT_FOUND = 1168;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct CREDENTIAL
        {
            public uint Flags;
            public uint Type;
            public string TargetName;
            public string Comment;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
            public uint CredentialBlobSize;
            public IntPtr CredentialBlob;
            public uint Persist;
            public uint AttributeCount;
            public IntPtr Attributes;
            public string TargetAlias;
            public string UserName;
        }

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CredWrite(ref CREDENTIAL userCredential, uint flags);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CredRead(
            string target,
            uint type,
            uint reservedFlag,
            out IntPtr credentialPtr);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CredDelete(string target, uint type, uint flags);

        [DllImport("advapi32.dll")]
        private static extern void CredFree(IntPtr credential);

        public static void Write(string target, SecureString secret)
        {
            if (String.IsNullOrWhiteSpace(target))
            {
                throw new ArgumentException("Credential target is empty.", "target");
            }
            if (secret == null || secret.Length == 0)
            {
                throw new ArgumentException("Credential value is empty.", "secret");
            }
            if (secret.Length > 256)
            {
                throw new ArgumentException("Credential value is too long.", "secret");
            }

            IntPtr blob = IntPtr.Zero;
            try
            {
                blob = Marshal.SecureStringToCoTaskMemUnicode(secret);
                CREDENTIAL credential = new CREDENTIAL();
                credential.Type = CRED_TYPE_GENERIC;
                credential.TargetName = target;
                credential.CredentialBlob = blob;
                credential.CredentialBlobSize = checked((uint)(secret.Length * 2));
                credential.Persist = CRED_PERSIST_LOCAL_MACHINE;
                credential.UserName = Environment.UserName;

                if (!CredWrite(ref credential, 0))
                {
                    ThrowLastError("write");
                }
            }
            finally
            {
                if (blob != IntPtr.Zero)
                {
                    Marshal.ZeroFreeCoTaskMemUnicode(blob);
                }
            }
        }

        public static bool TryRead(string target, out string value)
        {
            value = null;
            IntPtr credentialPtr = IntPtr.Zero;
            if (!CredRead(target, CRED_TYPE_GENERIC, 0, out credentialPtr))
            {
                int error = Marshal.GetLastWin32Error();
                if (error == ERROR_NOT_FOUND)
                {
                    return false;
                }
                ThrowLastError("read", error);
            }

            try
            {
                CREDENTIAL credential = (CREDENTIAL)Marshal.PtrToStructure(
                    credentialPtr,
                    typeof(CREDENTIAL));
                if (credential.CredentialBlob == IntPtr.Zero || credential.CredentialBlobSize == 0)
                {
                    throw new InvalidOperationException("Credential Manager returned an empty credential.");
                }
                if ((credential.CredentialBlobSize % 2) != 0 || credential.CredentialBlobSize > 512)
                {
                    throw new InvalidOperationException("Credential Manager returned an invalid credential size.");
                }
                value = Marshal.PtrToStringUni(
                    credential.CredentialBlob,
                    checked((int)(credential.CredentialBlobSize / 2)));
                if (String.IsNullOrEmpty(value))
                {
                    throw new InvalidOperationException("Credential Manager returned an empty credential.");
                }
                return true;
            }
            finally
            {
                CredFree(credentialPtr);
            }
        }

        public static bool TryReadSecure(string target, out SecureString value)
        {
            value = null;
            IntPtr credentialPtr = IntPtr.Zero;
            if (!CredRead(target, CRED_TYPE_GENERIC, 0, out credentialPtr))
            {
                int error = Marshal.GetLastWin32Error();
                if (error == ERROR_NOT_FOUND)
                {
                    return false;
                }
                ThrowLastError("read", error);
            }

            try
            {
                CREDENTIAL credential = (CREDENTIAL)Marshal.PtrToStructure(
                    credentialPtr,
                    typeof(CREDENTIAL));
                if (credential.CredentialBlob == IntPtr.Zero || credential.CredentialBlobSize == 0)
                {
                    throw new InvalidOperationException("Credential Manager returned an empty credential.");
                }
                if ((credential.CredentialBlobSize % 2) != 0 || credential.CredentialBlobSize > 512)
                {
                    throw new InvalidOperationException("Credential Manager returned an invalid credential size.");
                }

                int length = checked((int)(credential.CredentialBlobSize / 2));
                SecureString result = new SecureString();
                for (int index = 0; index < length; index++)
                {
                    char character = (char)Marshal.ReadInt16(credential.CredentialBlob, index * 2);
                    result.AppendChar(character);
                }
                result.MakeReadOnly();
                value = result;
                return true;
            }
            finally
            {
                CredFree(credentialPtr);
            }
        }

        public static bool Delete(string target)
        {
            if (CredDelete(target, CRED_TYPE_GENERIC, 0))
            {
                return true;
            }
            int error = Marshal.GetLastWin32Error();
            if (error == ERROR_NOT_FOUND)
            {
                return false;
            }
            ThrowLastError("delete", error);
            return false;
        }

        private static void ThrowLastError(string operation)
        {
            ThrowLastError(operation, Marshal.GetLastWin32Error());
        }

        private static void ThrowLastError(string operation, int error)
        {
            throw new Win32Exception(error, "Windows Credential Manager " + operation + " failed.");
        }
    }
}
'@ -ErrorAction Stop
}

function Get-TunnelCredentialTarget {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ConfigPath
    )

    $normalized = ([IO.Path]::GetFullPath($ConfigPath)).ToLowerInvariant()
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($normalized)
        $digest = $algorithm.ComputeHash($bytes)
        $hex = ([BitConverter]::ToString($digest) -replace "-", "").ToLowerInvariant()
    } finally {
        $algorithm.Dispose()
    }
    return "WindowsLocalMCP/SecureMcpTunnel/$hex"
}

function Set-TunnelCredential {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Target,
        [Parameter(Mandatory = $true)]
        [Security.SecureString]$Secret
    )

    Initialize-TunnelCredentialStore
    [WindowsLocalMcp.CredentialStore]::Write($Target, $Secret)
}

function Get-TunnelCredential {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Target
    )

    Initialize-TunnelCredentialStore
    $value = $null
    if ([WindowsLocalMcp.CredentialStore]::TryRead($Target, [ref]$value)) {
        return $value
    }
    return $null
}

function Get-TunnelCredentialSecure {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Target
    )

    Initialize-TunnelCredentialStore
    $value = $null
    if ([WindowsLocalMcp.CredentialStore]::TryReadSecure($Target, [ref]$value)) {
        return $value
    }
    return $null
}

function Remove-TunnelCredential {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Target
    )

    Initialize-TunnelCredentialStore
    return [WindowsLocalMcp.CredentialStore]::Delete($Target)
}

function ConvertFrom-TunnelSecureString {
    param(
        [Parameter(Mandatory = $true)]
        [Security.SecureString]$Secret
    )

    $pointer = [IntPtr]::Zero
    try {
        $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secret)
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
    } finally {
        if ($pointer -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
        }
    }
}

function Get-TunnelSha256 {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $stream = $null
    $algorithm = $null
    try {
        # configure-localmcp.bat が起動する Windows PowerShell で Utility
        # module を自動読込できない場合もあるため、標準 hash cmdlet へ依存しません。
        $stream = [IO.File]::Open(
            $Path,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            [IO.FileShare]::Read
        )
        $algorithm = [Security.Cryptography.SHA256]::Create()
        $bytes = $algorithm.ComputeHash($stream)
        return ([BitConverter]::ToString($bytes)).Replace('-', '').ToLowerInvariant()
    } catch {
        # hash 計算の例外は file path／アクセス／I/O に限定され、secret を
        # 扱いません。上位で原因を表示できるよう詳細を維持します。
        throw "Tunnel 対象ファイルの SHA-256 を確認できません: $($_.Exception.Message)"
    } finally {
        if ($null -ne $algorithm) { $algorithm.Dispose() }
        if ($null -ne $stream) { $stream.Dispose() }
    }
}

function Get-TunnelLocalMcpPythonPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ScriptRoot
    )

    foreach ($candidate in @(
        (Join-Path $ScriptRoot "runtime\Scripts\python.exe"),
        (Join-Path $ScriptRoot ".venv\Scripts\python.exe")
    )) {
        try {
            $item = Get-Item -LiteralPath $candidate -Force -ErrorAction Stop
            if (-not $item.PSIsContainer -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) {
                return (Resolve-Path -LiteralPath $candidate -ErrorAction Stop).Path
            }
        } catch {
            # run-server.ps1 と同じ専用 Python だけを候補にします。
        }
    }
    return $null
}

function Test-TunnelLocalMcpConfiguration {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PythonPath,
        [Parameter(Mandatory = $true)]
        [string]$ConfigPath
    )

    $previousConfig = $env:LOCAL_MCP_CONFIG
    $previousRoot = $env:LOCAL_MCP_ROOT
    try {
        $env:LOCAL_MCP_CONFIG = $ConfigPath
        Remove-Item Env:LOCAL_MCP_ROOT -ErrorAction SilentlyContinue
        $probe = @(
            "from windows_local_mcp.config import load_settings",
            "settings = load_settings()",
            "print('workspace_root=' + str(settings.workspace_root))",
            "print('data_dir=' + str(settings.data_dir))"
        ) -join "; "
        $output = @(& $PythonPath -I -X utf8 -B -c $probe 2>$null)
        if ($LASTEXITCODE -ne 0) {
            return [PSCustomObject]@{ Valid = $false; WorkspaceRoot = $null; DataDir = $null }
        }
        $workspaceLine = $output | Where-Object { $_.ToString().StartsWith("workspace_root=", [StringComparison]::Ordinal) } | Select-Object -Last 1
        $dataLine = $output | Where-Object { $_.ToString().StartsWith("data_dir=", [StringComparison]::Ordinal) } | Select-Object -Last 1
        if ($null -eq $workspaceLine -or $null -eq $dataLine) {
            return [PSCustomObject]@{ Valid = $false; WorkspaceRoot = $null; DataDir = $null }
        }
        return [PSCustomObject]@{
            Valid = $true
            WorkspaceRoot = $workspaceLine.ToString().Substring("workspace_root=".Length)
            DataDir = $dataLine.ToString().Substring("data_dir=".Length)
        }
    } catch {
        return [PSCustomObject]@{ Valid = $false; WorkspaceRoot = $null; DataDir = $null }
    } finally {
        if ($null -eq $previousConfig) {
            Remove-Item Env:LOCAL_MCP_CONFIG -ErrorAction SilentlyContinue
        } else {
            $env:LOCAL_MCP_CONFIG = $previousConfig
        }
        if ($null -eq $previousRoot) {
            Remove-Item Env:LOCAL_MCP_ROOT -ErrorAction SilentlyContinue
        } else {
            $env:LOCAL_MCP_ROOT = $previousRoot
        }
    }
}

function Test-TunnelPathInside {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Candidate,
        [Parameter(Mandatory = $true)]
        [string]$Parent
    )

    $candidatePath = [IO.Path]::GetFullPath($Candidate).TrimEnd('\', '/')
    $parentPath = [IO.Path]::GetFullPath($Parent).TrimEnd('\', '/')
    return $candidatePath.Equals($parentPath, [StringComparison]::OrdinalIgnoreCase) -or
        $candidatePath.StartsWith($parentPath + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)
}

function Resolve-TunnelExecutable {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [string[]]$ForbiddenRoots = @(),
        [switch]$AllowMissing
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        if ($AllowMissing) { return $null }
        throw "Tunnel client の path が空です。"
    }
    try {
        $rawResolved = [IO.Path]::GetFullPath($Path)
        foreach ($root in @($ForbiddenRoots | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })) {
            # Resolve 後の実体だけでなく、入力された path 自体も禁止領域で
            # 判定します。workspace 内の junction 経由の実行ファイルを
            # 外部の実体として自動採用しないためです。
            if (Test-TunnelPathInside -Candidate $rawResolved -Parent $root) {
                throw "Tunnel client を workspace、data_dir、またはリポジトリ内から自動採用できません。"
            }
        }
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if ($item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
            throw "Tunnel client は通常の実行ファイルで指定してください。"
        }
        $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
        foreach ($root in @($ForbiddenRoots | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })) {
            if (Test-TunnelPathInside -Candidate $resolved -Parent $root) {
                throw "Tunnel client を workspace、data_dir、またはリポジトリ内から自動採用できません。"
            }
        }
        return $resolved
    } catch {
        if ($AllowMissing) { return $null }
        if ($_.Exception.Message -like "Tunnel client*") { throw }
        throw "Tunnel client を確認できません。公式配布物を用意してから再実行してください。"
    }
}

function Get-TunnelClientCandidates {
    param(
        [string]$PreferredPath,
        [string]$StateRoot,
        [string[]]$ForbiddenRoots = @()
    )

    $paths = [System.Collections.Generic.List[string]]::new()
    foreach ($candidate in @(
        $PreferredPath,
        $env:TUNNEL_CLIENT_BIN
    )) {
        if (-not [string]::IsNullOrWhiteSpace($candidate)) {
            $null = $paths.Add($candidate)
        }
    }

    foreach ($name in @("tunnel-client.exe", "tunnel-client")) {
        try {
            $command = Get-Command $name -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($null -ne $command -and $command.Source) {
                $null = $paths.Add($command.Source)
            }
        } catch {
            # PATH 上の候補を確認できない場合は次の候補へ進みます。
        }
    }

    $downloadRoots = [System.Collections.Generic.List[string]]::new()
    if (-not [string]::IsNullOrWhiteSpace($env:USERPROFILE)) {
        $null = $downloadRoots.Add((Join-Path $env:USERPROFILE "Desktop"))
        $null = $downloadRoots.Add((Join-Path $env:USERPROFILE "Downloads"))
        $null = $downloadRoots.Add((Join-Path $env:USERPROFILE "OneDrive\Desktop"))
        $null = $downloadRoots.Add((Join-Path $env:USERPROFILE "OneDrive\Downloads"))
    }
    if (-not [string]::IsNullOrWhiteSpace($env:OneDrive)) {
        $null = $downloadRoots.Add((Join-Path $env:OneDrive "Desktop"))
        $null = $downloadRoots.Add((Join-Path $env:OneDrive "Downloads"))
    }
    foreach ($root in @($downloadRoots | Select-Object -Unique)) {
        if (-not (Test-Path -LiteralPath $root -PathType Container)) { continue }
        $null = $paths.Add((Join-Path $root "tunnel-client.exe"))
        foreach ($directory in @(Get-ChildItem -LiteralPath $root -Directory -Force -Filter "tunnel-client*" -ErrorAction SilentlyContinue | Select-Object -First 50)) {
            $null = $paths.Add((Join-Path $directory.FullName "tunnel-client.exe"))
        }
    }

    $profileRoots = [System.Collections.Generic.List[string]]::new()
    foreach ($root in @(
        $env:TUNNEL_CLIENT_PROFILE_DIR,
        $env:TUNNEL_CLIENT_STATE_DIR,
        (Join-Path $StateRoot "tunnel-client"),
        (Join-Path $env:LOCALAPPDATA "tunnel-client"),
        (Join-Path $env:APPDATA "tunnel-client")
    )) {
        if (-not [string]::IsNullOrWhiteSpace($root)) {
            $null = $profileRoots.Add($root)
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($env:USERPROFILE)) {
        $null = $profileRoots.Add((Join-Path $env:USERPROFILE ".config\tunnel-client"))
    }

    foreach ($root in @($profileRoots | Select-Object -Unique)) {
        if (-not (Test-Path -LiteralPath $root -PathType Container)) { continue }
        foreach ($file in @(Get-ChildItem -LiteralPath $root -File -Force -Recurse -ErrorAction SilentlyContinue | Select-Object -First 200)) {
            try {
                $content = Get-Content -Raw -Encoding UTF8 -LiteralPath $file.FullName -ErrorAction Stop
                foreach ($match in [regex]::Matches(
                    $content,
                    '(?im)^\s*(?:tunnel[_-]?client|executable|binary|path)\s*:\s*["'']?(?<path>[^"''\r\n]*tunnel-client(?:\.exe)?)')) {
                    if ($match.Groups["path"].Success) {
                        $null = $paths.Add($match.Groups["path"].Value.Trim())
                    }
                }
            } catch {
                # 既存設定は未検証入力なので、読めない候補を信用しません。
            }
        }
    }

    $result = [System.Collections.Generic.List[object]]::new()
    foreach ($candidate in @($paths | Select-Object -Unique)) {
        try {
            $resolved = Resolve-TunnelExecutable -Path $candidate -ForbiddenRoots $ForbiddenRoots
            $hash = Get-TunnelSha256 -Path $resolved
            if (-not ($result | Where-Object { $_.Path.Equals($resolved, [StringComparison]::OrdinalIgnoreCase) })) {
                $null = $result.Add([PSCustomObject]@{ Path = $resolved; Hash = $hash })
            }
        } catch {
            # 未検証の候補は自動採用しません。
        }
    }
    return @($result)
}

function Test-TunnelId {
    param([AllowEmptyString()][string]$TunnelId)
    return $TunnelId -match '^tunnel_[0-9a-f]{32}$'
}

function ConvertTo-TunnelYamlScalar {
    param([Parameter(Mandatory = $true)][string]$Value)
    return "'" + $Value.Replace("'", "''") + "'"
}

function ConvertTo-TunnelCommandArgument {
    param([Parameter(Mandatory = $true)][string]$Value)
    if ($Value -match '[\r\n]') {
        throw "Tunnel profile の path に改行は使用できません。"
    }
    # tunnel-client v0.0.10 の MCP command parser は drive path の backslash を
    # 安全に保持しないため、PowerShell でも等価な forward slash へ正規化します。
    $normalized = $Value.Replace('\', '/')
    return '"' + $normalized.Replace('"', '\"') + '"'
}

function ConvertFrom-TunnelYamlScalar {
    param([AllowEmptyString()][string]$Value)
    $text = $Value.Trim()
    if ($text.Length -ge 2 -and $text.StartsWith("'") -and $text.EndsWith("'")) {
        return $text.Substring(1, $text.Length - 2).Replace("''", "'")
    }
    if ($text.Length -ge 2 -and $text.StartsWith('"') -and $text.EndsWith('"')) {
        return $text.Substring(1, $text.Length - 2).Replace('\"', '"')
    }
    return $text
}

function Get-TunnelComparablePath {
    param([Parameter(Mandatory = $true)][string]$Path)

    if ($Path -match '[\r\n]') {
        throw "Tunnel command の path に改行は使用できません。"
    }
    $full = [IO.Path]::GetFullPath($Path.Replace('/', [IO.Path]::DirectorySeparatorChar))
    $item = Get-Item -LiteralPath $full -Force -ErrorAction Stop
    if ($item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw "Tunnel command の path は通常のファイルである必要があります。"
    }
    return ([IO.Path]::GetFullPath($item.FullName)).TrimEnd('\', '/')
}

function New-TunnelProfileContent {
    param(
        [Parameter(Mandatory = $true)][string]$TunnelId,
        [Parameter(Mandatory = $true)][string]$ServerScript,
        [Parameter(Mandatory = $true)][string]$ConfigPath,
        [Parameter(Mandatory = $true)][string]$PidFile,
        [Parameter(Mandatory = $true)][string]$HealthUrlFile
    )

    if (-not (Test-TunnelId -TunnelId $TunnelId)) {
        throw "Tunnel ID の形式が正しくありません。"
    }
    $serverArgument = ConvertTo-TunnelCommandArgument -Value $ServerScript
    $configArgument = ConvertTo-TunnelCommandArgument -Value $ConfigPath
    $mcpCommand = "powershell.exe -NoProfile -File $serverArgument -Config $configArgument"
    $lines = @(
        "config_version: 1",
        "control_plane:",
        "  base_url: https://api.openai.com",
        "  tunnel_id: $TunnelId",
        "  api_key: env:WLMCP_TUNNEL_RUNTIME_API_KEY",
        "  poll_timeout: 30000ms",
        "  poll_deadline_guardrail: 5000ms",
        "mcp:",
        "  commands:",
        "    - channel: main",
        "      command: $(ConvertTo-TunnelYamlScalar -Value $mcpCommand)",
        "health:",
        "  listen_addr: 127.0.0.1:0",
        "  url_file: $(ConvertTo-TunnelYamlScalar -Value $HealthUrlFile)",
        "admin_ui:",
        "  open_browser: false",
        "process:",
        "  pid_file: $(ConvertTo-TunnelYamlScalar -Value $PidFile)",
        "log:",
        "  level: warn",
        "  format: struct-text"
    )
    return ($lines -join [Environment]::NewLine) + [Environment]::NewLine
}

function Get-TunnelProfileInfo {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [string]$ServerScript,
        [string]$ConfigPath
    )

    $content = Get-Content -Raw -Encoding UTF8 -LiteralPath $Path -ErrorAction Stop
    $tunnelMatch = [regex]::Match($content, '(?im)^\s*tunnel_id\s*:\s*["'']?(?<id>tunnel_[0-9a-f]{32})["'']?\s*$')
    $apiKeyMode = "missing"
    $apiKeyReference = $null
    $apiKeyMatch = [regex]::Match($content, '(?im)^\s*api_key\s*:\s*(?<value>[^\r\n]+)')
    if ($apiKeyMatch.Success) {
        $reference = $apiKeyMatch.Groups["value"].Value.Trim().Trim([char[]]@([char]39, [char]34))
        $apiKeyReference = $reference
        if ($reference.StartsWith("env:", [StringComparison]::OrdinalIgnoreCase)) {
            $apiKeyMode = "environment-reference"
        } elseif ($reference.StartsWith("file:", [StringComparison]::OrdinalIgnoreCase)) {
            $apiKeyMode = "file-reference"
        } else {
            $apiKeyMode = "literal"
        }
    } elseif (-not [string]::IsNullOrWhiteSpace($env:CONTROL_PLANE_API_KEY)) {
        $apiKeyMode = "ambient-environment"
    }

    $pidFile = $null
    $pidMatch = [regex]::Match($content, '(?im)^\s*pid_file\s*:\s*(?<value>[^\r\n]+)')
    if ($pidMatch.Success) {
        $pidFile = ConvertFrom-TunnelYamlScalar -Value $pidMatch.Groups["value"].Value
        if (-not [IO.Path]::IsPathRooted($pidFile)) {
            $pidFile = Join-Path (Split-Path -Parent (Resolve-Path -LiteralPath $Path).Path) $pidFile
        }
    }
    $healthUrlFile = $null
    $healthMatch = [regex]::Match($content, '(?im)^\s*url_file\s*:\s*(?<value>[^\r\n]+)')
    if ($healthMatch.Success) {
        $healthUrlFile = ConvertFrom-TunnelYamlScalar -Value $healthMatch.Groups["value"].Value
        if (-not [IO.Path]::IsPathRooted($healthUrlFile)) {
            $healthUrlFile = Join-Path (Split-Path -Parent (Resolve-Path -LiteralPath $Path).Path) $healthUrlFile
        }
    }

    $matchesLocalMcp = $false
    if (-not [string]::IsNullOrWhiteSpace($ServerScript) -and -not [string]::IsNullOrWhiteSpace($ConfigPath)) {
        try {
            $commandMatches = [regex]::Matches($content, '(?im)^\s*command\s*:\s*(?<value>[^\r\n]+)\s*$')
            if ($commandMatches.Count -eq 1) {
                $command = ConvertFrom-TunnelYamlScalar -Value $commandMatches[0].Groups["value"].Value
                $parsedCommand = [regex]::Match(
                    $command,
                    '^powershell\.exe\s+-NoProfile\s+-File\s+"(?<server>[^"\r\n]+)"\s+-Config\s+"(?<config>[^"\r\n]+)"$'
                )
                if ($parsedCommand.Success) {
                    $actualServer = Get-TunnelComparablePath -Path $parsedCommand.Groups["server"].Value
                    $actualConfig = Get-TunnelComparablePath -Path $parsedCommand.Groups["config"].Value
                    $expectedServer = Get-TunnelComparablePath -Path $ServerScript
                    $expectedConfig = Get-TunnelComparablePath -Path $ConfigPath
                    $matchesLocalMcp =
                        $actualServer.Equals($expectedServer, [StringComparison]::OrdinalIgnoreCase) -and
                        $actualConfig.Equals($expectedConfig, [StringComparison]::OrdinalIgnoreCase)
                }
            }
        } catch {
            $matchesLocalMcp = $false
        }
    }

    return [PSCustomObject]@{
        Path = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
        TunnelId = if ($tunnelMatch.Success) { $tunnelMatch.Groups["id"].Value } else { $null }
        ApiKeyMode = $apiKeyMode
        ApiKeyReference = $apiKeyReference
        MatchesLocalMcp = $matchesLocalMcp
        PidFile = $pidFile
        HealthUrlFile = $healthUrlFile
        Content = $content
    }
}

function Get-TunnelProfileFiles {
    param(
        [Parameter(Mandatory = $true)][string]$StateRoot
    )

    $files = [System.Collections.Generic.List[string]]::new()
    foreach ($candidate in @(
        $env:TUNNEL_CLIENT_PROFILE_FILE,
        $env:TUNNEL_CLIENT_CONFIG
    )) {
        if (-not [string]::IsNullOrWhiteSpace($candidate) -and (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            $null = $files.Add((Resolve-Path -LiteralPath $candidate).Path)
        }
    }

    $roots = [System.Collections.Generic.List[string]]::new()
    foreach ($root in @(
        (Join-Path $StateRoot "tunnel-profiles"),
        $env:TUNNEL_CLIENT_PROFILE_DIR,
        (Join-Path $StateRoot "tunnel-client"),
        $env:TUNNEL_CLIENT_STATE_DIR,
        (Join-Path $env:LOCALAPPDATA "tunnel-client"),
        (Join-Path $env:APPDATA "tunnel-client")
    )) {
        if (-not [string]::IsNullOrWhiteSpace($root)) {
            $null = $roots.Add($root)
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($env:USERPROFILE)) {
        $null = $roots.Add((Join-Path $env:USERPROFILE ".config\tunnel-client"))
    }

    # Named profile/runtime aliases are resolved only to the standard profile
    # directories.  An alias cannot make a workspace-owned executable trusted.
    foreach ($alias in @($env:TUNNEL_CLIENT_PROFILE, $env:TUNNEL_CLIENT_RUNTIME)) {
        if ([string]::IsNullOrWhiteSpace($alias) -or $alias -match '[\\/:]') { continue }
        foreach ($root in @($roots | Select-Object -Unique)) {
            $null = $files.Add((Join-Path $root "$alias.yaml"))
            $null = $files.Add((Join-Path $root "$alias.yml"))
        }
    }

    foreach ($root in @($roots | Select-Object -Unique)) {
        if (-not (Test-Path -LiteralPath $root -PathType Container)) { continue }
        foreach ($file in @(Get-ChildItem -LiteralPath $root -File -Force -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.Extension -in @(".yaml", ".yml") } | Select-Object -First 200)) {
            try { $null = $files.Add((Resolve-Path -LiteralPath $file.FullName).Path) } catch { }
        }
    }
    return @($files | Select-Object -Unique)
}

function Find-TunnelProfileCandidates {
    param(
        [Parameter(Mandatory = $true)][string]$StateRoot,
        [Parameter(Mandatory = $true)][string]$ServerScript,
        [Parameter(Mandatory = $true)][string]$ConfigPath,
        [string[]]$ForbiddenRoots = @()
    )

    $result = [System.Collections.Generic.List[object]]::new()
    foreach ($path in @(Get-TunnelProfileFiles -StateRoot $StateRoot)) {
        try {
            $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
            $resolved = (Resolve-Path -LiteralPath $path).Path
            $forbidden = $false
            foreach ($root in @($ForbiddenRoots | Where-Object { $_ })) {
                if (Test-TunnelPathInside -Candidate $resolved -Parent $root) { $forbidden = $true; break }
            }
            if ($forbidden) { continue }
            $info = Get-TunnelProfileInfo -Path $resolved -ServerScript $ServerScript -ConfigPath $ConfigPath
            if (-not $info.MatchesLocalMcp -or [string]::IsNullOrWhiteSpace($info.TunnelId)) { continue }
            if ($info.ApiKeyMode -eq "literal") { continue }
            if (-not ($result | Where-Object { $_.Path.Equals($resolved, [StringComparison]::OrdinalIgnoreCase) })) {
                $null = $result.Add($info)
            }
        } catch {
            # 既存 profile は未信頼入力として扱い、読めないものを候補にしません。
        }
    }
    return @($result)
}

function Get-TunnelStatePath {
    param(
        [Parameter(Mandatory = $true)][string]$StateRoot,
        [string]$ConfigPath
    )
    if ([string]::IsNullOrWhiteSpace($ConfigPath)) {
        return Join-Path $StateRoot "secure-mcp-tunnel.json"
    }
    $fingerprint = (Get-TunnelCredentialTarget -ConfigPath $ConfigPath).Split('/')[-1]
    return Join-Path (Join-Path $StateRoot "tunnel-state") "$fingerprint.json"
}

function Get-TunnelProfilePath {
    param(
        [Parameter(Mandatory = $true)][string]$StateRoot,
        [Parameter(Mandatory = $true)][string]$ConfigPath
    )
    $fingerprint = (Get-TunnelCredentialTarget -ConfigPath $ConfigPath).Split('/')[-1]
    return Join-Path (Join-Path $StateRoot "tunnel-profiles") "localmcp-$fingerprint.yaml"
}

function Read-TunnelState {
    param([Parameter(Mandatory = $true)][string]$StatePath)
    if (-not (Test-Path -LiteralPath $StatePath -PathType Leaf)) { return $null }
    try {
        $raw = Get-Content -Raw -Encoding UTF8 -LiteralPath $StatePath -ErrorAction Stop
        if ($raw -match '(?im)"(?:api[_-]?key|secret|token)"\s*:') {
            throw "Tunnel state に秘密情報らしい項目があります。"
        }
        $state = $raw | ConvertFrom-Json -ErrorAction Stop
        if ($null -eq $state -or $state.version -ne 1) {
            throw "Tunnel state の version が対応していません。"
        }
        return $state
    } catch {
        if ($_.Exception.Message -like "Tunnel state*") { throw }
        throw "Secure MCP Tunnel の state を読み取れません。configure-localmcp.bat から診断してください。"
    }
}

function Get-TunnelMutexName {
    param([Parameter(Mandatory = $true)][string]$ConfigPath)
    $target = Get-TunnelCredentialTarget -ConfigPath $ConfigPath
    return "Local\$($target.Replace('/', '-'))"
}

function Write-TunnelProfileStaging {
    param(
        [Parameter(Mandatory = $true)][string]$Content,
        [Parameter(Mandatory = $true)][string]$DestinationPath
    )
    $destinationDirectory = Split-Path -Parent $DestinationPath
    New-Item -ItemType Directory -Path $destinationDirectory -Force | Out-Null
    # tunnel-client v0.0.10 の --profile-file は path が .yaml で終わることを
    # config_source 検証で要求します。atomic install と同じ directory 内に置き、
    # staging 中も有効な profile-file 名を維持します。
    $baseName = [IO.Path]::GetFileNameWithoutExtension($DestinationPath)
    $temporaryName = "$baseName.tmp-$PID-$([Guid]::NewGuid().ToString('N')).yaml"
    $temporary = Join-Path $destinationDirectory $temporaryName
    [IO.File]::WriteAllText($temporary, $Content, [Text.UTF8Encoding]::new($false))
    return $temporary
}

function Install-TunnelProfileStaging {
    param(
        [Parameter(Mandatory = $true)][string]$StagingPath,
        [Parameter(Mandatory = $true)][string]$DestinationPath
    )
    $backup = $null
    if (Test-Path -LiteralPath $DestinationPath -PathType Leaf) {
        $backup = "$DestinationPath.backup-$([DateTime]::UtcNow.ToString('yyyyMMdd-HHmmssfff'))-$([Guid]::NewGuid().ToString('N'))"
        Copy-Item -LiteralPath $DestinationPath -Destination $backup -Force -ErrorAction Stop
    }
    Move-Item -LiteralPath $StagingPath -Destination $DestinationPath -Force -ErrorAction Stop
    return [PSCustomObject]@{ BackupPath = $backup; DestinationPath = $DestinationPath }
}

function Save-TunnelStateAtomic {
    param(
        [Parameter(Mandatory = $true)][object]$State,
        [Parameter(Mandatory = $true)][string]$StatePath
    )
    New-Item -ItemType Directory -Path (Split-Path -Parent $StatePath) -Force | Out-Null
    $backup = $null
    if (Test-Path -LiteralPath $StatePath -PathType Leaf) {
        $backup = "$StatePath.backup-$([DateTime]::UtcNow.ToString('yyyyMMdd-HHmmssfff'))-$([Guid]::NewGuid().ToString('N'))"
        Copy-Item -LiteralPath $StatePath -Destination $backup -Force -ErrorAction Stop
    }
    $temporary = "$StatePath.tmp-$PID-$([Guid]::NewGuid().ToString('N'))"
    try {
        $json = $State | ConvertTo-Json -Depth 6 -Compress
        [IO.File]::WriteAllText($temporary, $json + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
        Move-Item -LiteralPath $temporary -Destination $StatePath -Force -ErrorAction Stop
    } finally {
        if (Test-Path -LiteralPath $temporary -PathType Leaf) {
            Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
        }
    }
    return [PSCustomObject]@{ BackupPath = $backup; StatePath = $StatePath }
}

function Restore-TunnelFileBackup {
    param(
        [Parameter(Mandatory = $true)][string]$DestinationPath,
        [string]$BackupPath
    )
    if (-not [string]::IsNullOrWhiteSpace($BackupPath) -and (Test-Path -LiteralPath $BackupPath -PathType Leaf)) {
        Move-Item -LiteralPath $BackupPath -Destination $DestinationPath -Force -ErrorAction Stop
    } elseif (Test-Path -LiteralPath $DestinationPath -PathType Leaf) {
        Remove-Item -LiteralPath $DestinationPath -Force -ErrorAction Stop
    }
}

function Remove-TunnelStagingFile {
    param([string]$Path)
    if (-not [string]::IsNullOrWhiteSpace($Path) -and (Test-Path -LiteralPath $Path -PathType Leaf)) {
        Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    }
}

function Test-TunnelProfileBinding {
    param(
        [Parameter(Mandatory = $true)][object]$State,
        [Parameter(Mandatory = $true)][string]$ConfigPath,
        [Parameter(Mandatory = $true)][string]$ServerScript,
        [Parameter(Mandatory = $true)][string]$ProfileRoot,
        [Parameter(Mandatory = $true)][string]$StateRoot,
        [string[]]$ForbiddenRoots = @()
    )

    try {
        foreach ($name in @("config_path", "profile_path", "profile_sha256", "profile_scope", "tunnel_client_path", "tunnel_client_sha256", "tunnel_id", "pid_file", "health_url_file", "credential_mode")) {
            if ([string]::IsNullOrWhiteSpace([string]$State.$name)) {
                return [PSCustomObject]@{ Valid = $false; ReasonCode = "state_incomplete"; Message = "Tunnel state の必須項目がありません。" }
            }
        }
        if ([bool]$State.enabled -ne $true) {
            return [PSCustomObject]@{ Valid = $false; ReasonCode = "disabled"; Message = "Tunnel integration は無効です。" }
        }
        if (-not [IO.Path]::GetFullPath([string]$State.config_path).Equals([IO.Path]::GetFullPath($ConfigPath), [StringComparison]::OrdinalIgnoreCase)) {
            return [PSCustomObject]@{ Valid = $false; ReasonCode = "config_mismatch"; Message = "Tunnel 設定が active config と一致しません。" }
        }
        if (-not (Test-TunnelId -TunnelId ([string]$State.tunnel_id))) {
            return [PSCustomObject]@{ Valid = $false; ReasonCode = "tunnel_id_invalid"; Message = "Tunnel ID の形式が正しくありません。" }
        }
        $profileScope = ([string]$State.profile_scope).ToLowerInvariant()
        if ($profileScope -notin @("managed", "external")) {
            return [PSCustomObject]@{ Valid = $false; ReasonCode = "profile_scope"; Message = "Tunnel profile の保存場所が対応していません。" }
        }
        foreach ($stateFileName in @("pid_file", "health_url_file")) {
            $stateFilePath = [IO.Path]::GetFullPath([string]$State.$stateFileName)
            if (-not (Test-TunnelPathInside -Candidate $stateFilePath -Parent $StateRoot)) {
                return [PSCustomObject]@{ Valid = $false; ReasonCode = "state_location"; Message = "Tunnel state の補助ファイルが管理領域の外にあります。" }
            }
            if (Test-Path -LiteralPath $stateFilePath -PathType Leaf) {
                $stateItem = Get-Item -LiteralPath $stateFilePath -Force -ErrorAction Stop
                if (($stateItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                    return [PSCustomObject]@{ Valid = $false; ReasonCode = "state_location"; Message = "Tunnel state の補助ファイルが reparse point です。" }
                }
            }
        }
        $profilePath = Resolve-TunnelExecutable -Path ([string]$State.profile_path) -ForbiddenRoots $ForbiddenRoots
        $clientPath = Resolve-TunnelExecutable -Path ([string]$State.tunnel_client_path) -ForbiddenRoots $ForbiddenRoots
        if ($profileScope -eq "managed" -and -not (Test-TunnelPathInside -Candidate $profilePath -Parent $ProfileRoot)) {
            return [PSCustomObject]@{ Valid = $false; ReasonCode = "profile_location"; Message = "Tunnel profile が管理対象の場所にありません。" }
        }
        if ((Get-TunnelSha256 -Path $profilePath) -ne ([string]$State.profile_sha256).ToLowerInvariant()) {
            return [PSCustomObject]@{ Valid = $false; ReasonCode = "profile_changed"; Message = "Tunnel profile が変更されています。" }
        }
        if ((Get-TunnelSha256 -Path $clientPath) -ne ([string]$State.tunnel_client_sha256).ToLowerInvariant()) {
            return [PSCustomObject]@{ Valid = $false; ReasonCode = "client_changed"; Message = "Tunnel client の実行ファイルが変更されています。" }
        }
        $profile = Get-TunnelProfileInfo -Path $profilePath -ServerScript $ServerScript -ConfigPath $ConfigPath
        if ($profile.TunnelId -ne [string]$State.tunnel_id -or -not $profile.MatchesLocalMcp) {
            return [PSCustomObject]@{ Valid = $false; ReasonCode = "profile_binding"; Message = "Tunnel profile の Tunnel ID または MCP command が一致しません。" }
        }
        if ($profile.ApiKeyMode -eq "literal") {
            return [PSCustomObject]@{ Valid = $false; ReasonCode = "secret_in_profile"; Message = "Tunnel profile に API Key の平文が含まれています。" }
        }
        $credentialMode = ([string]$State.credential_mode).ToLowerInvariant()
        if ($credentialMode -eq "credential_manager") {
            if ([string]$State.credential_target -ne (Get-TunnelCredentialTarget -ConfigPath $ConfigPath)) {
                return [PSCustomObject]@{ Valid = $false; ReasonCode = "credential_binding"; Message = "保存済み credential が active config に結び付いていません。" }
            }
        } elseif ($credentialMode -eq "profile_reference") {
            if ($profile.ApiKeyMode -notin @("environment-reference", "file-reference", "ambient-environment")) {
                return [PSCustomObject]@{ Valid = $false; ReasonCode = "credential_missing"; Message = "既存 Tunnel profile から安全な API Key 参照を確認できません。" }
            }
        } else {
            return [PSCustomObject]@{ Valid = $false; ReasonCode = "credential_binding"; Message = "Tunnel の認証情報設定が対応していません。" }
        }
        return [PSCustomObject]@{
            Valid = $true
            ReasonCode = "ok"
            Message = "Tunnel profile の整合性を確認しました。"
            ProfilePath = $profilePath
            ClientPath = $clientPath
            Profile = $profile
        }
    } catch {
        return [PSCustomObject]@{ Valid = $false; ReasonCode = "profile_invalid"; Message = "Tunnel profile を安全に検証できません。" }
    }
}

function Get-TunnelFailedChecks {
    param(
        [string]$Stdout,
        [string]$Stderr
    )

    $text = "$Stdout`n$Stderr"
    $checks = [Collections.Generic.List[string]]::new()
    foreach ($match in [regex]::Matches($text, '(?im)^\s*FAILED_CHECKS\s+(?<checks>[A-Za-z0-9_., -]+?)\s*$')) {
        foreach ($name in ($match.Groups['checks'].Value -split '[\s,]+')) {
            $normalized = $name.Trim().ToLowerInvariant()
            if ($normalized -match '^[a-z][a-z0-9_]*$' -and -not $checks.Contains($normalized)) {
                $checks.Add($normalized)
            }
        }
    }
    return @($checks)
}

function Resolve-TunnelServerRuntime {
    param(
        [Parameter(Mandatory = $true)][string]$ScriptRoot,
        [AllowNull()][object]$State,
        [switch]$VerifyApprovedHostRuntime
    )

    $developmentServer = (Resolve-Path -LiteralPath (Join-Path $ScriptRoot "run-server.ps1") -ErrorAction Stop).Path
    $runtimeKind = if (
        $null -ne $State -and
        -not [string]::IsNullOrWhiteSpace([string]$State.server_runtime_kind)
    ) {
        ([string]$State.server_runtime_kind).ToLowerInvariant()
    } else {
        "development"
    }

    if ($runtimeKind -eq "development") {
        return [PSCustomObject]@{
            Valid = $true
            Kind = "development"
            ServerScript = $developmentServer
            PythonPath = Get-TunnelLocalMcpPythonPath -ScriptRoot $ScriptRoot
            Message = "開発用 runtime を使用します。"
        }
    }
    if ($runtimeKind -ne "approved_host") {
        return [PSCustomObject]@{
            Valid = $false
            Kind = $runtimeKind
            ServerScript = $null
            PythonPath = $null
            Message = "Tunnel state の server runtime 種別が対応していません。"
        }
    }

    try {
        if ($null -eq $State -or [string]::IsNullOrWhiteSpace([string]$State.server_script_path)) {
            throw "Approved Host 用 server path が Tunnel state にありません。"
        }
        $serverScript = (Resolve-Path -LiteralPath ([string]$State.server_script_path) -ErrorAction Stop).Path
        $installRoot = Split-Path -Parent $serverScript
        $programFilesRoots = @(
            [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles),
            [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFilesX86)
        ) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Select-Object -Unique
        if (-not ($programFilesRoots | Where-Object { Test-TunnelPathInside -Candidate $serverScript -Parent $_ })) {
            throw "Approved Host server は Program Files 配下にある必要があります。"
        }
        if ([IO.Path]::GetFileName($serverScript) -ne "run-server.ps1") {
            throw "Approved Host server のファイル名が正しくありません。"
        }
        $pythonPath = Join-Path $installRoot "runtime\Scripts\python.exe"
        $installedVerifierPath = Join-Path $installRoot "verify-approved-host-runtime.ps1"
        $launcherVerifierPath = Join-Path $ScriptRoot "verify-approved-host-runtime.ps1"
        foreach ($requiredPath in @($pythonPath, $installedVerifierPath, $launcherVerifierPath)) {
            if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
                throw "Approved Host 運用 runtime の必須ファイルがありません: $requiredPath"
            }
        }
        if (
            -not [string]::IsNullOrWhiteSpace([string]$State.server_script_sha256) -and
            (Get-TunnelSha256 -Path $serverScript) -ne ([string]$State.server_script_sha256).ToLowerInvariant()
        ) {
            throw "Approved Host の run-server.ps1 が Tunnel 設定後に変更されています。"
        }
        if ($VerifyApprovedHostRuntime) {
            $windowsPowerShell = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
            if (-not (Test-Path -LiteralPath $windowsPowerShell -PathType Leaf)) {
                throw "Windows PowerShell 5.1 を確認できません。"
            }
            # 検証対象側の script を先に信用せず、現在実行中の配布物と同じ
            # verifier から Program Files runtime を検査します。
            $verifyOutput = @(& $windowsPowerShell -NoProfile -File $launcherVerifierPath -InstallRoot $installRoot 2>&1)
            if ($LASTEXITCODE -ne 0) {
                throw "Approved Host 運用 runtime の変更不能性検証に失敗しました。"
            }
        }
        return [PSCustomObject]@{
            Valid = $true
            Kind = "approved_host"
            ServerScript = $serverScript
            PythonPath = (Resolve-Path -LiteralPath $pythonPath -ErrorAction Stop).Path
            Message = "変更不能な Approved Host 運用 runtime を使用します。"
        }
    } catch {
        return [PSCustomObject]@{
            Valid = $false
            Kind = "approved_host"
            ServerScript = $null
            PythonPath = $null
            Message = $_.Exception.Message
        }
    }
}

function Get-TunnelFailureDetail {
    param(
        [string]$Stdout,
        [string]$Stderr,
        [int]$ExitCode
    )

    $text = "$Stdout`n$Stderr"
    $failedChecks = @(Get-TunnelFailedChecks -Stdout $Stdout -Stderr $Stderr)
    $failureClass = "tunnel_client_failed"
    $failureCode = "doctor_unknown_failure"

    if ($ExitCode -eq 0) {
        $failureClass = "ok"
        $failureCode = "ok"
    } elseif ($failedChecks -contains "config_source") {
        $failureClass = "profile_invalid"
        $failureCode = "doctor_config_source"
    } elseif ($failedChecks -contains "profile_load") {
        $failureClass = "profile_invalid"
        $failureCode = "doctor_profile_load"
    } elseif ($failedChecks -contains "control_plane_api_key") {
        $failureClass = "auth_failed"
        $failureCode = "doctor_control_plane_api_key"
    } elseif ($failedChecks -contains "tunnel_id") {
        $failureClass = "tunnel_id_invalid"
        $failureCode = "doctor_tunnel_id"
    } elseif ($failedChecks -contains "mcp_command_executable") {
        $failureClass = "server_start_failed"
        $failureCode = "doctor_mcp_command_executable"
    } elseif ($failedChecks -contains "mcp_server_reachable") {
        $failureClass = "server_start_failed"
        $failureCode = "doctor_mcp_server_reachable"
    } elseif ($failedChecks -contains "health_listener") {
        $failureClass = "health_listener_failed"
        $failureCode = "doctor_health_listener"
    } elseif ($failedChecks -contains "oauth_metadata") {
        $failureClass = "oauth_metadata_failed"
        $failureCode = "doctor_oauth_metadata"
    } elseif (@($failedChecks | Where-Object { $_ -like "control_plane_*" }).Count -gt 0) {
        $failureClass = "control_plane_failed"
        $failureCode = "doctor_control_plane"
    } elseif ($failedChecks.Count -gt 0) {
        $failureClass = "tunnel_client_failed"
        $failureCode = "doctor_reported_checks"
    } elseif ($text -match '(?i)(?:http[^\r\n]{0,20})?\b401\b|unauthori[sz]ed|invalid.{0,20}(?:api|runtime).{0,20}key') {
        $failureClass = "auth_failed"
        $failureCode = "doctor_auth_rejected"
    } elseif ($text -match '(?i)(?:http[^\r\n]{0,20})?\b403\b|forbidden|permission denied') {
        $failureClass = "permission_denied"
        $failureCode = "doctor_permission_denied"
    } elseif ($text -match '(?i)(?:tunnel[^\r\n]{0,40}(?:\b404\b|not found|unknown)|invalid tunnel)') {
        $failureClass = "tunnel_id_invalid"
        $failureCode = "doctor_tunnel_not_found"
    } elseif ($text -match '(?i)(?:parse|decode|load|read).{0,40}(?:profile|yaml|config)|(?:profile|yaml|config).{0,40}(?:parse|syntax|unsupported|unknown field|invalid config_version)') {
        $failureClass = "profile_invalid"
        $failureCode = "doctor_profile_parse"
    } elseif ($text -match '(?i)(?:mcp|command|server|powershell).{0,40}(?:missing|not found|unavailable|cannot|failed|spawn|start)') {
        $failureClass = "server_start_failed"
        $failureCode = "doctor_server_start"
    }

    # doctor の生出力には将来 secret が含まれる可能性があるため保持しません。
    return [PSCustomObject]@{
        FailureClass = $failureClass
        FailureCode = $failureCode
        FailedChecks = @($failedChecks)
    }
}

function Get-TunnelFailureClass {
    param(
        [string]$Stdout,
        [string]$Stderr,
        [int]$ExitCode
    )
    return (Get-TunnelFailureDetail -Stdout $Stdout -Stderr $Stderr -ExitCode $ExitCode).FailureClass
}

function New-TunnelProcessStartInfo {
    param(
        [Parameter(Mandatory = $true)][string]$ClientPath,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Security.SecureString]$Credential
    )
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $ClientPath
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $false
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.WorkingDirectory = Split-Path -Parent $ClientPath
    $quoted = foreach ($argument in $Arguments) {
        if ($argument -match '[\r\n]') { throw "Tunnel client の引数に改行があります。" }
        if ($argument -match '[\s"]') { '"' + $argument.Replace('"', '\"') + '"' } else { $argument }
    }
    $info.Arguments = $quoted -join ' '
    $plain = $null
    if ($null -ne $Credential) {
        $plain = ConvertFrom-TunnelSecureString -Secret $Credential
        if ([string]::IsNullOrEmpty($plain)) { throw "Runtime API Key を取得できません。" }
        # The profile contains only this env: reference.  The value exists only
        # in the child process environment and is never persisted by this script.
        $info.EnvironmentVariables["WLMCP_TUNNEL_RUNTIME_API_KEY"] = $plain
    }
    return [PSCustomObject]@{ StartInfo = $info }
}

function Invoke-TunnelClientDoctor {
    param(
        [Parameter(Mandatory = $true)][string]$ClientPath,
        [Parameter(Mandatory = $true)][string]$ProfilePath,
        [Security.SecureString]$Credential
    )
    $process = $null
    $plain = $null
    try {
        $prepared = New-TunnelProcessStartInfo -ClientPath $ClientPath -Arguments @(
            "doctor", "--profile-file", $ProfilePath, "--explain"
        ) -Credential $Credential
        $process = [Diagnostics.Process]::new()
        $process.StartInfo = $prepared.StartInfo
        if (-not $process.Start()) { throw "start failed" }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $process.WaitForExit()
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        $exitCode = $process.ExitCode
        $failure = Get-TunnelFailureDetail -Stdout $stdout -Stderr $stderr -ExitCode $exitCode
        return [PSCustomObject]@{
            Succeeded = ($exitCode -eq 0)
            ExitCode = $exitCode
            FailureClass = $failure.FailureClass
            FailureCode = $failure.FailureCode
            FailedChecks = @($failure.FailedChecks)
        }
    } catch {
        return [PSCustomObject]@{
            Succeeded = $false
            ExitCode = -1
            FailureClass = "tunnel_client_unavailable"
            FailureCode = "doctor_process_start_failed"
            FailedChecks = @()
        }
    } finally {
        $plain = $null
        if ($null -ne $process) { $process.Dispose() }
    }
}

function Start-TunnelClientProcess {
    param(
        [Parameter(Mandatory = $true)][string]$ClientPath,
        [Parameter(Mandatory = $true)][string]$ProfilePath,
        [Security.SecureString]$Credential
    )
    $process = $null
    $plain = $null
    $subscriptions = @()
    try {
        $prepared = New-TunnelProcessStartInfo -ClientPath $ClientPath -Arguments @(
            "run", "--profile-file", $ProfilePath
        ) -Credential $Credential
        $process = [Diagnostics.Process]::new()
        $process.StartInfo = $prepared.StartInfo
        if (-not $process.Start()) { throw "start failed" }

        # Drain both pipes but intentionally discard all output.  A third-party
        # client must not be able to place an API key in this launcher's console.
        $subscriptions += Register-ObjectEvent -InputObject $process -EventName OutputDataReceived -Action { $null = $EventArgs.Data }
        $subscriptions += Register-ObjectEvent -InputObject $process -EventName ErrorDataReceived -Action { $null = $EventArgs.Data }
        $process.BeginOutputReadLine()
        $process.BeginErrorReadLine()
        return [PSCustomObject]@{ Process = $process; Subscriptions = @($subscriptions) }
    } catch {
        foreach ($subscription in @($subscriptions)) {
            try { Unregister-Event -SubscriptionId $subscription.Id -ErrorAction SilentlyContinue } catch { }
            try {
                if ($subscription.Action -is [Management.Automation.Job]) {
                    Remove-Job -Job $subscription.Action -Force -ErrorAction SilentlyContinue
                }
            } catch { }
        }
        if ($null -ne $process) { $process.Dispose() }
        throw "Tunnel client を起動できません。"
    } finally {
        $plain = $null
    }
}

function Wait-TunnelClientProcess {
    param([Parameter(Mandatory = $true)][object]$Started)
    try {
        $Started.Process.WaitForExit()
        return $Started.Process.ExitCode
    } finally {
        foreach ($subscription in @($Started.Subscriptions)) {
            try { Unregister-Event -SubscriptionId $subscription.Id -ErrorAction SilentlyContinue } catch { }
            try {
                if ($subscription.Action -is [Management.Automation.Job]) {
                    Remove-Job -Job $subscription.Action -Force -ErrorAction SilentlyContinue
                }
            } catch { }
        }
        $Started.Process.Dispose()
    }
}

function Get-TunnelProcessStatus {
    param(
        [Parameter(Mandatory = $true)][string]$PidFile,
        [Parameter(Mandatory = $true)][string]$ClientPath,
        [Parameter(Mandatory = $true)][string]$ProfilePath
    )
    $findMatchingProcess = {
        try {
            $clientFullPath = (Resolve-Path -LiteralPath $ClientPath -ErrorAction Stop).Path
            $profileFullPath = [IO.Path]::GetFullPath($ProfilePath)
            $matches = @(
                Get-CimInstance -ClassName Win32_Process -ErrorAction Stop |
                    Where-Object {
                        $candidatePath = [string]$_.ExecutablePath
                        $candidateCommand = [string]$_.CommandLine
                        $candidatePath -and
                            $candidatePath.Equals($clientFullPath, [StringComparison]::OrdinalIgnoreCase) -and
                            $candidateCommand.IndexOf($profileFullPath, [StringComparison]::OrdinalIgnoreCase) -ge 0
                    }
            )
            if ($matches.Count -eq 1) {
                return [PSCustomObject]@{ Status = "running"; ProcessId = [int]$matches[0].ProcessId }
            }
            if ($matches.Count -gt 1) {
                return [PSCustomObject]@{ Status = "indeterminate"; ProcessId = $null }
            }
            return [PSCustomObject]@{ Status = "absent"; ProcessId = $null }
        } catch {
            return [PSCustomObject]@{ Status = "indeterminate"; ProcessId = $null }
        }
    }
    if (-not (Test-Path -LiteralPath $PidFile -PathType Leaf)) {
        return & $findMatchingProcess
    }
    try {
        $raw = (Get-Content -Raw -Encoding UTF8 -LiteralPath $PidFile -ErrorAction Stop).Trim()
        $processId = 0
        if (-not [int]::TryParse($raw, [ref]$processId) -or $processId -le 0) {
            return [PSCustomObject]@{ Status = "indeterminate"; ProcessId = $null }
        }
        $process = Get-Process -Id $processId -ErrorAction SilentlyContinue
        if ($null -eq $process) {
            $discovered = & $findMatchingProcess
            if ($discovered.Status -eq "running") { return $discovered }
            return [PSCustomObject]@{ Status = "stale"; ProcessId = $processId }
        }
        $cim = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId=$processId" -ErrorAction Stop
        $actualPath = if ($cim.ExecutablePath) { (Resolve-Path -LiteralPath $cim.ExecutablePath -ErrorAction Stop).Path } else { "" }
        $commandLine = [string]$cim.CommandLine
        if ($actualPath.Equals($ClientPath, [StringComparison]::OrdinalIgnoreCase) -and
            $commandLine.IndexOf($ProfilePath, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
            return [PSCustomObject]@{ Status = "running"; ProcessId = $processId }
        }
        return [PSCustomObject]@{ Status = "indeterminate"; ProcessId = $processId }
    } catch {
        return [PSCustomObject]@{ Status = "indeterminate"; ProcessId = $processId }
    }
}

function Get-TunnelHealthUrl {
    param([Parameter(Mandatory = $true)][string]$HealthUrlFile)
    if (-not (Test-Path -LiteralPath $HealthUrlFile -PathType Leaf)) { return $null }
    try {
        $raw = (Get-Content -Raw -Encoding UTF8 -LiteralPath $HealthUrlFile -ErrorAction Stop).Trim()
        $uri = $null
        if (-not [Uri]::TryCreate($raw, [UriKind]::Absolute, [ref]$uri)) { return $null }
        if ($uri.Scheme -notin @("http", "https") -or $uri.Host -notin @("127.0.0.1", "localhost", "::1")) { return $null }
        return $uri.AbsoluteUri.TrimEnd('/')
    } catch {
        return $null
    }
}

function Test-TunnelReady {
    param([Parameter(Mandatory = $true)][string]$HealthUrl)
    try {
        $response = Invoke-WebRequest -UseBasicParsing -MaximumRedirection 0 -Uri ($HealthUrl + "/readyz") -Method Get -TimeoutSec 3 -ErrorAction Stop
        return [int]$response.StatusCode -eq 200
    } catch {
        return $false
    }
}

function Wait-TunnelReady {
    param(
        [Parameter(Mandatory = $true)][string]$HealthUrlFile,
        [int]$TimeoutSeconds = 20
    )
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        $url = Get-TunnelHealthUrl -HealthUrlFile $HealthUrlFile
        if ($null -ne $url -and (Test-TunnelReady -HealthUrl $url)) {
            return [PSCustomObject]@{ Ready = $true; Url = $url }
        }
        Start-Sleep -Milliseconds 500
    }
    return [PSCustomObject]@{ Ready = $false; Url = Get-TunnelHealthUrl -HealthUrlFile $HealthUrlFile }
}

function Show-TunnelOnboardingGuide {
    Write-Host ""
    Write-Host "ChatGPT Secure MCP Tunnel の設定" -ForegroundColor Cyan
    Write-Host "Tunnel は、Windows 上の LocalMCP を公開ポートなしで ChatGPT から利用するための接続です。"
    Write-Host "Tunnel ID は接続先の識別子です。既存 Tunnel があれば新規作成せず再利用できます。"
    Write-Host "Tunnel ID の確認・作成: https://platform.openai.com/settings/organization/tunnels" -ForegroundColor Cyan
    Write-Host "形式: tunnel_ に続く 32 桁の小文字 hexadecimal（例: tunnel_0123456789abcdef0123456789abcdef）"
    Write-Host "Runtime API Key は tunnel-client が OpenAI Tunnel へ接続する認証情報です。"
    Write-Host "Runtime API keys: https://platform.openai.com/settings/organization/api-keys" -ForegroundColor Cyan
    Write-Host "Restricted key を選び、Tunnels Read + Use の最小権限にしてください。"
    Write-Host "秘密情報の全文は作成時だけ表示され、後から Platform 上で再表示できません。紛失時は新しい key を作成します。"
    Write-Host "API Key は他人へ送信しないでください。ここで入力した値は Windows のユーザー資格情報領域へ保存します。"
}

function Show-TunnelClientInstallGuide {
    Write-Host ""
    Write-Host "tunnel-client が見つかりません。" -ForegroundColor Yellow
    Write-Host "tunnel-client は LocalMCP と OpenAI Tunnel の間を接続するために必要です。"
    Write-Host "公式 Tunnels 管理画面のダウンロード案内: https://platform.openai.com/settings/organization/tunnels" -ForegroundColor Cyan
    Write-Host "公式リリース一覧: https://github.com/openai/tunnel-client/releases/latest" -ForegroundColor Cyan
    Write-Host "公式配布物を workspace の外へインストールし、絶対 path を指定してから configure-localmcp.bat を再実行してください。"
}

function Show-TunnelFailureGuide {
    param(
        [Parameter(Mandatory = $true)][string]$FailureClass,
        [string]$ReasonCode = "",
        [string]$Detail = "",
        [string[]]$FailedChecks = @(),
        [int]$ExitCode = -1
    )

    if (-not [string]::IsNullOrWhiteSpace($ReasonCode)) {
        Write-Host "診断コード: $ReasonCode" -ForegroundColor Gray
    }
    if ($FailedChecks.Count -gt 0) {
        Write-Host "失敗した tunnel-client doctor check: $($FailedChecks -join ', ')" -ForegroundColor Gray
    }
    if ($ExitCode -ge 0) {
        Write-Host "tunnel-client doctor 終了コード: $ExitCode" -ForegroundColor Gray
    }
    if (-not [string]::IsNullOrWhiteSpace($Detail)) {
        Write-Host "検出内容: $Detail" -ForegroundColor Yellow
    }

    switch ($FailureClass) {
        "auth_failed" {
            if ($ReasonCode -eq "doctor_control_plane_api_key") {
                Write-Host "tunnel-client が Runtime API Key を profile の参照先から取得・検証できませんでした。入力値、環境変数参照、Restricted key の Tunnels Read + Use を確認してください。" -ForegroundColor Yellow
            } else {
                Write-Host "Runtime API Key が認証で拒否されたか、安全な資格情報領域から取得できません。Platform で Restricted key（Tunnels Read + Use）を確認し、必要なら新しい key を作成して再設定してください。" -ForegroundColor Yellow
            }
        }
        "permission_denied" {
            Write-Host "Tunnel への権限がありません。Runtime key の Tunnels Read + Use と、対象 Tunnel の組織・workspace 関連付けを確認してください。" -ForegroundColor Yellow
        }
        "tunnel_id_invalid" {
            if ($ReasonCode -eq "doctor_tunnel_id") {
                Write-Host "tunnel-client の Tunnel ID check に失敗しました。profile 内の値と `tunnel_` + 小文字 hexadecimal 32 桁の形式を確認してください。" -ForegroundColor Yellow
            } else {
                Write-Host "Tunnel ID が存在しないか形式が正しくありません。Platform の Tunnels 管理画面から対象 ID を再確認してください。" -ForegroundColor Yellow
            }
        }
        "profile_invalid" {
            Write-Host "Tunnel profile の読み込み、構文、保存場所、または保存済み整合性の検証に失敗しました。上記の診断コードに対応する箇所を確認してください。" -ForegroundColor Yellow
        }
        "server_start_failed" {
            Write-Host "Tunnel から LocalMCP server を起動できません。config.toml、run-server.ps1、専用 Python 環境を確認してください。" -ForegroundColor Yellow
        }
        "tunnel_client_unavailable" {
            Write-Host "tunnel-client を起動または実行できません。実行ファイルの path、権限、公式配布物を確認してください。" -ForegroundColor Yellow
        }
        "health_listener_failed" {
            Write-Host "Tunnel のローカル health listener を確保できません。listen address の競合、使用中 port、またはローカル socket 設定を確認してください。" -ForegroundColor Yellow
        }
        "oauth_metadata_failed" {
            Write-Host "LocalMCP の OAuth metadata 検証に失敗しました。MCP endpoint の応答と認証 metadata を確認してください。" -ForegroundColor Yellow
        }
        "control_plane_failed" {
            Write-Host "OpenAI Tunnel control plane の検証に失敗しました。ネットワーク、TLS、proxy、Tunnel の組織関連付けを確認してください。" -ForegroundColor Yellow
        }
        default {
            Write-Host "Tunnel の検証に失敗しました。tunnel-client doctor --profile-file を再実行できるよう、configure-localmcp.bat から診断・再設定してください。" -ForegroundColor Yellow
        }
    }
}

function Show-TunnelDoctorFailureGuide {
    param([Parameter(Mandatory = $true)][object]$DoctorResult)

    Show-TunnelFailureGuide `
        -FailureClass ([string]$DoctorResult.FailureClass) `
        -ReasonCode ([string]$DoctorResult.FailureCode) `
        -FailedChecks @($DoctorResult.FailedChecks) `
        -ExitCode ([int]$DoctorResult.ExitCode)
}
