param(
    [Parameter(Mandatory=$true)][string]$Path,
    [Parameter(Mandatory=$true)][string]$OutFile,
    [int]$SlideIndex = 4
)

$ErrorActionPreference = 'Stop'

# Measure RENDERED text bounds for every shape on one slide (layout-safety proof).
$ppt = New-Object -ComObject PowerPoint.Application

try {
    $pres = $ppt.Presentations.Open($Path, $true, $false, $false)
    $slide = $pres.Slides.Item($SlideIndex)

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("slide=$SlideIndex slideWidth=$($pres.PageSetup.SlideWidth) slideHeight=$($pres.PageSetup.SlideHeight)")

    foreach ($sh in $slide.Shapes) {
        $txt = ''
        try { $txt = $sh.TextFrame2.TextRange.Text } catch {}
        if ($null -eq $txt) { $txt = '' }
        $txt = $txt -replace "`r", ' | ' -replace "`n", ' '
        if ($txt.Length -gt 90) { $txt = $txt.Substring(0, 90) }

        $bt = ''; $bh = ''; $bl = ''; $bw = ''
        try {
            $tr = $sh.TextFrame2.TextRange
            $bt = [math]::Round($tr.BoundTop, 2)
            $bh = [math]::Round($tr.BoundHeight, 2)
            $bl = [math]::Round($tr.BoundLeft, 2)
            $bw = [math]::Round($tr.BoundWidth, 2)
        } catch {}

        $lines.Add(("attop={0,8:N2} atleft={1,8:N2} w={2,8:N2} h={3,8:N2} | boundTop={4,8} boundH={5,8} boundL={6,8} boundW={7,8} | {8} :: {9}" -f `
            $sh.Top, $sh.Left, $sh.Width, $sh.Height, $bt, $bh, $bl, $bw, $sh.Name, $txt))
    }

    $lines | Set-Content -Path $OutFile -Encoding UTF8
    $pres.Close()
}
finally {
    $ppt.Quit()
    [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($ppt)
}
Write-Output "measured -> $OutFile"
