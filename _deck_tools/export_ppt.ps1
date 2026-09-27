param(
    [Parameter(Mandatory=$true)][string]$Path,
    [Parameter(Mandatory=$true)][string]$OutDir
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }

# Export every slide to PNG so before/after renders can be pixel-diffed.
$ppt = New-Object -ComObject PowerPoint.Application

try {
    $pres = $ppt.Presentations.Open($Path, $true, $false, $false)
    for ($i = 1; $i -le $pres.Slides.Count; $i++) {
        $out = Join-Path $OutDir ("slide{0}.png" -f $i)
        $pres.Slides.Item($i).Export($out, "PNG", 1600, 900)
    }
    $pres.Close()
}
finally {
    $ppt.Quit()
    [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($ppt)
}
Write-Output "exported -> $OutDir"
