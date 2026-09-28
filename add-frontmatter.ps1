$base = "C:\Users\36059\AppData\Roaming\TRAE SOLO CN\ModularData\ai-agent\work-mode-projects\6aba1a2c6740cf8e5a3e9eea\my-blog"
$files = Get-ChildItem "$base\content\posts\pwn\*.md"

foreach ($f in $files) {
    $content = Get-Content $f.FullName -Raw -Encoding UTF8
    $lines = Get-Content $f.FullName -Encoding UTF8

    $title = $f.BaseName
    foreach ($line in $lines) {
        if ($line -match '^#\s+(.+)') {
            $title = $Matches[1]
            break
        }
        if ($line -match '^###\s+(.+)') {
            $title = $Matches[1]
            break
        }
    }

    $date = $f.LastWriteTime.ToString("yyyy-MM-ddTHH:mm:ss+08:00")

    $frontMatter = @"
---
title: "$title"
date: $date
draft: false
categories: ["Pwn"]
tags: ["CTF", "Pwn", "i春秋"]
---

"@

    $frontMatter + $content | Set-Content $f.FullName -Encoding UTF8
    Write-Host "Processed: $($f.Name) -> $title"
}

Write-Host "`nDone! Processed $($files.Count) files."
