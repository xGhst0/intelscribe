# Generates the IntelScribe application icon (a teal report page with a security
# shield) as crisp PNGs at multiple sizes and assembles a multi-resolution ICO.
# Drawn with GDI+ in a 256x256 coordinate space and re-rasterised per size.
#
#   powershell -ExecutionPolicy Bypass -File tools\make-icon.ps1

Add-Type -AssemblyName System.Drawing

$iconsDir = Join-Path $PSScriptRoot "..\crates\app\icons"
New-Item -ItemType Directory -Force $iconsDir | Out-Null

function New-RoundedRect([single]$x, [single]$y, [single]$w, [single]$h, [single]$r) {
    $p = New-Object System.Drawing.Drawing2D.GraphicsPath
    $d = $r * 2
    $p.AddArc($x, $y, $d, $d, 180, 90)
    $p.AddArc($x + $w - $d, $y, $d, $d, 270, 90)
    $p.AddArc($x + $w - $d, $y + $h - $d, $d, $d, 0, 90)
    $p.AddArc($x, $y + $h - $d, $d, $d, 90, 90)
    $p.CloseFigure()
    return $p
}

function Draw-Icon([System.Drawing.Graphics]$g) {
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic

    # Background: diagonal teal gradient in a rounded square.
    $bg = New-RoundedRect 0 0 256 256 52
    $c1 = [System.Drawing.Color]::FromArgb(255, 10, 58, 71)    # deep teal
    $c2 = [System.Drawing.Color]::FromArgb(255, 21, 188, 207)  # bright teal
    $grad = New-Object System.Drawing.Drawing2D.LinearGradientBrush(
        (New-Object System.Drawing.Point(0, 0)),
        (New-Object System.Drawing.Point(256, 256)), $c1, $c2)
    $g.FillPath($grad, $bg)

    # Document drop shadow.
    $shadow = New-RoundedRect 72 52 116 152 12
    $sb = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(60, 0, 0, 0))
    $g.FillPath($sb, $shadow)

    # White page.
    $page = New-RoundedRect 68 46 116 152 12
    $white = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::White)
    $g.FillPath($white, $page)

    # Folded top-right corner.
    $fold = New-Object System.Drawing.Drawing2D.GraphicsPath
    $fold.AddPolygon(@(
        (New-Object System.Drawing.PointF(156, 46)),
        (New-Object System.Drawing.PointF(184, 46)),
        (New-Object System.Drawing.PointF(184, 74))))
    $foldBrush = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(255, 214, 227, 231))
    $g.FillPath($foldBrush, $fold)

    # Title bar (teal) + body lines (grey).
    $teal = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(255, 20, 184, 201))
    $grey = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(255, 203, 215, 219))
    $g.FillPath($teal, (New-RoundedRect 86 74 78 11 4))
    $g.FillPath($grey, (New-RoundedRect 86 98 92 7 3))
    $g.FillPath($grey, (New-RoundedRect 86 112 84 7 3))
    $g.FillPath($grey, (New-RoundedRect 86 126 92 7 3))
    $g.FillPath($grey, (New-RoundedRect 86 140 60 7 3))

    # Security shield, overlapping the page's lower-right.
    $cx = 176.0; $top = 150.0; $sw = 78.0; $sh = 86.0
    $half = $sw / 2
    $shield = New-Object System.Drawing.Drawing2D.GraphicsPath
    $shield.AddArc($cx - $half, $top, 16, 16, 180, 90)
    $shield.AddArc($cx + $half - 16, $top, 16, 16, 270, 90)
    $shield.AddLine($cx + $half, $top + 16, $cx + $half, $top + $sh * 0.45)
    $shield.AddBezier(
        $cx + $half, ($top + $sh * 0.45),
        $cx + $half * 0.7, ($top + $sh * 0.85),
        $cx, ($top + $sh),
        $cx, ($top + $sh))
    $shield.AddBezier(
        $cx, ($top + $sh),
        $cx, ($top + $sh),
        $cx - $half * 0.7, ($top + $sh * 0.85),
        $cx - $half, ($top + $sh * 0.45))
    $shield.CloseFigure()

    # White ring behind the shield for separation from the page.
    $ringPen = New-Object System.Drawing.Pen ([System.Drawing.Color]::White), 7
    $ringPen.LineJoin = [System.Drawing.Drawing2D.LineJoin]::Round
    $g.DrawPath($ringPen, $shield)
    $shieldFill = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(255, 12, 124, 143))
    $g.FillPath($shieldFill, $shield)

    # White checkmark.
    $check = New-Object System.Drawing.Drawing2D.GraphicsPath
    $check.AddLines(@(
        (New-Object System.Drawing.PointF(($cx - 17), ($top + 40))),
        (New-Object System.Drawing.PointF(($cx - 4), ($top + 53))),
        (New-Object System.Drawing.PointF(($cx + 20), ($top + 26)))))
    $checkPen = New-Object System.Drawing.Pen ([System.Drawing.Color]::White), 9
    $checkPen.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
    $checkPen.EndCap = [System.Drawing.Drawing2D.LineCap]::Round
    $checkPen.LineJoin = [System.Drawing.Drawing2D.LineJoin]::Round
    $g.DrawPath($checkPen, $check)
}

function Render-Size([int]$size) {
    $bmp = New-Object System.Drawing.Bitmap($size, $size, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.Clear([System.Drawing.Color]::Transparent)
    $g.ScaleTransform($size / 256.0, $size / 256.0)
    Draw-Icon $g
    $g.Dispose()
    return $bmp
}

# Standalone PNGs Tauri references.
$pngSizes = @{ "32x32.png" = 32; "64x64.png" = 64; "128x128.png" = 128; "128x128@2x.png" = 256; "icon.png" = 512 }
foreach ($name in $pngSizes.Keys) {
    $bmp = Render-Size $pngSizes[$name]
    $bmp.Save((Join-Path $iconsDir $name), [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
}

# Multi-resolution ICO built from PNG-encoded entries.
$icoSizes = @(256, 128, 64, 48, 32, 16)
$pngBytes = @()
foreach ($s in $icoSizes) {
    $bmp = Render-Size $s
    $ms = New-Object System.IO.MemoryStream
    $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
    $pngBytes += , $ms.ToArray()
    $bmp.Dispose(); $ms.Dispose()
}

$out = New-Object System.IO.MemoryStream
$bw = New-Object System.IO.BinaryWriter($out)
$bw.Write([uint16]0); $bw.Write([uint16]1); $bw.Write([uint16]$icoSizes.Count)
$offset = 6 + 16 * $icoSizes.Count
for ($i = 0; $i -lt $icoSizes.Count; $i++) {
    $s = $icoSizes[$i]
    $dim = if ($s -ge 256) { 0 } else { $s }
    $bw.Write([byte]$dim); $bw.Write([byte]$dim); $bw.Write([byte]0); $bw.Write([byte]0)
    $bw.Write([uint16]1); $bw.Write([uint16]32)
    $bw.Write([uint32]$pngBytes[$i].Length); $bw.Write([uint32]$offset)
    $offset += $pngBytes[$i].Length
}
foreach ($b in $pngBytes) { $bw.Write($b) }
$bw.Flush()
[System.IO.File]::WriteAllBytes((Join-Path $iconsDir "icon.ico"), $out.ToArray())
$bw.Dispose(); $out.Dispose()

Write-Output "Icons written to $((Resolve-Path $iconsDir).Path)"
