[CmdletBinding()]
param(
    [string]$Image = "floria:local-supply-chain",
    [string]$ArtifactsDir = "target/supply-chain",
    [string]$CosignKey = $env:COSIGN_KEY,
    [switch]$SkipBuild,
    [switch]$SkipCosign
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Require-Command {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [string]$InstallHint
    )

    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "Required command '$Name' was not found. $InstallHint"
    }
}

Require-Command "docker" "Install Docker Desktop or another Docker-compatible runtime."
Require-Command "trivy" "Install with 'winget install AquaSecurity.Trivy' or from https://aquasecurity.github.io/trivy/."
Require-Command "syft" "Install with 'winget install Anchore.Syft' or from https://github.com/anchore/syft."
if (-not $SkipCosign) {
    Require-Command "cosign" "Install with 'winget install Sigstore.Cosign' or from https://docs.sigstore.dev/cosign/."
}

$artifactRoot = [System.IO.Path]::GetFullPath($ArtifactsDir)
New-Item -ItemType Directory -Force -Path $artifactRoot | Out-Null

$startedOn = (Get-Date).ToUniversalTime().ToString("o")

if (-not $SkipBuild) {
    docker build --file Dockerfile --tag $Image .
}

trivy image --severity HIGH,CRITICAL --exit-code 1 --scanners vuln $Image

$sbomPath = Join-Path $artifactRoot "floria-image.spdx.json"
syft "docker:$Image" -o "spdx-json=$sbomPath"

$imageId = docker image inspect $Image --format "{{.Id}}"
$imageSha256 = $imageId -replace "^sha256:", ""
$repoRoot = (git rev-parse --show-toplevel).Trim()
$gitCommit = (git rev-parse HEAD).Trim()
$gitRemote = (git config --get remote.origin.url)
if ([string]::IsNullOrWhiteSpace($gitRemote)) {
    $gitRemote = "file://$repoRoot"
}
$gitStatus = (git status --porcelain | Out-String).Trim()
$dockerfileHash = (Get-FileHash -Algorithm SHA256 -Path "Dockerfile").Hash.ToLowerInvariant()
$finishedOn = (Get-Date).ToUniversalTime().ToString("o")

$statement = [ordered]@{
    "_type" = "https://in-toto.io/Statement/v1"
    "subject" = @(
        [ordered]@{
            "name" = $Image
            "digest" = [ordered]@{
                "sha256" = $imageSha256
            }
        }
    )
    "predicateType" = "https://slsa.dev/provenance/v1"
    "predicate" = [ordered]@{
        "buildDefinition" = [ordered]@{
            "buildType" = "https://contrix.local/floria/docker-build/v1"
            "externalParameters" = [ordered]@{
                "image" = $Image
                "dockerfile" = "Dockerfile"
                "context" = "."
            }
            "internalParameters" = [ordered]@{
                "script" = "scripts/local-supply-chain.ps1"
                "localOnly" = $true
                "published" = $false
                "gitDirty" = -not [string]::IsNullOrWhiteSpace($gitStatus)
            }
            "resolvedDependencies" = @(
                [ordered]@{
                    "uri" = "git+$gitRemote"
                    "digest" = [ordered]@{
                        "gitCommit" = $gitCommit
                    }
                },
                [ordered]@{
                    "uri" = "file://Dockerfile"
                    "digest" = [ordered]@{
                        "sha256" = $dockerfileHash
                    }
                }
            )
        }
        "runDetails" = [ordered]@{
            "builder" = [ordered]@{
                "id" = "local:docker"
            }
            "metadata" = [ordered]@{
                "invocationId" = [guid]::NewGuid().ToString()
                "startedOn" = $startedOn
                "finishedOn" = $finishedOn
            }
        }
    }
}

$provenancePath = Join-Path $artifactRoot "floria-slsa-provenance.in-toto.json"
$statement | ConvertTo-Json -Depth 20 | Set-Content -Path $provenancePath -Encoding utf8

if ($SkipCosign) {
    Write-Host "Skipped cosign signing because -SkipCosign was set."
} elseif ([string]::IsNullOrWhiteSpace($CosignKey)) {
    Write-Warning "Skipping cosign signing because -CosignKey or COSIGN_KEY is not set."
    Write-Warning "Generate a local key with 'cosign generate-key-pair' and rerun with -CosignKey .\cosign.key."
} else {
    $bundlePath = Join-Path $artifactRoot "floria-slsa-provenance.sigstore.json"
    cosign sign-blob --yes --key $CosignKey --tlog-upload=false --bundle $bundlePath $provenancePath
}

Write-Host "SBOM: $sbomPath"
Write-Host "SLSA provenance: $provenancePath"
