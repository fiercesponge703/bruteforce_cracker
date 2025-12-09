$hashcatExe   = "DIRECTORY"
$hashFilesDir = "DIRECTORY"


$runPythonFirst = $false
$pythonArgs     = "--procs 12 --chunk 20000 --time-limit 60 --timeout-per-test 300"


if (-not (Test-Path $hashcatExe)) {
    Write-Host "hashcat.exe не найден по пути: $hashcatExe" -ForegroundColor Red
    exit 1
}
if (-not (Test-Path $hashFilesDir)) {
    Write-Host "Папка с хэшами не найдена: $hashFilesDir" -ForegroundColor Red
    exit 1
}


function Run-Hashcat {
    param(
        [int]      $Mode,
        [string]   $HashFileName,
        [string[]] $MaskArgs,
        [string]   $OutLogName
    )

    $hashcatDir   = Split-Path $hashcatExe
    $hashFilePath = Join-Path $hashFilesDir $HashFileName
    $outLogPath   = Join-Path $hashFilesDir $OutLogName

    if (-not (Test-Path $hashFilePath)) {
        Write-Host "Файл с хэшом не найден: $hashFilePath" -ForegroundColor Yellow
        return
    }

    Write-Host ""
    Write-Host "=== hashcat: mode=$Mode, hashfile=$hashFilePath ===" -ForegroundColor Cyan
    Write-Host "Лог: $outLogPath"
    Write-Host "Маска/аргументы: $($MaskArgs -join ' ')"
    Write-Host ""

    Push-Location $hashcatDir
    try {
        
        & $hashcatExe -m $Mode -a 3 $hashFilePath @MaskArgs --status --status-timer=5 --potfile-disable 2>&1 |
            Out-File -FilePath $outLogPath -Encoding utf8
    }
    finally {
        Pop-Location
    }
}


if ($runPythonFirst) {
    Write-Host "Запуск Python-раннера run_all_python.py..." -ForegroundColor Green
    Push-Location $hashFilesDir
    try {
       
        python .\run_all_python.py $pythonArgs.Split(' ')
    }
    catch {
        Write-Host "Ошибка при запуске run_all_python.py: $_" -ForegroundColor Red
    }
    finally {
        Pop-Location
    }
}

Write-Host ""
Write-Host "=== Серия тестов hashcat ===" -ForegroundColor Green


'''Run-Hashcat -Mode 0 -HashFileName "md5.txt"          -MaskArgs @("?d?d?d?d?d?d") `
            -OutLogName "hashcat_md5_easy.txt"

Run-Hashcat -Mode 0 -HashFileName "md5_medium.txt"   -MaskArgs @("-1","0123456789abcdefghijklmnopqrstuvwxyz","?1?1?1?1?1?1") `
            -OutLogName "hashcat_md5_medium.txt"

Run-Hashcat -Mode 0 -HashFileName "md5_hard.txt"     -MaskArgs @("-1","0123456789abcdefghijklmnopqrstuvwxyz","?1?1?1?1?1?1?1") `
            -OutLogName "hashcat_md5_hard.txt"

Run-Hashcat -Mode 0 -HashFileName "md5_veryhard.txt" -MaskArgs @("-1","0123456789abcdefghijklmnopqrstuvwxyz","?1?1?1?1?1?1?1?1") `
            -OutLogName "hashcat_md5_veryhard.txt"


Run-Hashcat -Mode 100 -HashFileName "sha1.txt"          -MaskArgs @("?d?d?d?d?d?d") `
            -OutLogName "hashcat_sha1_easy.txt"

Run-Hashcat -Mode 100 -HashFileName "sha1_medium.txt"   -MaskArgs @("-1","0123456789abcdefghijklmnopqrstuvwxyz","?1?1?1?1?1?1") `
            -OutLogName "hashcat_sha1_medium.txt"

Run-Hashcat -Mode 100 -HashFileName "sha1_hard.txt"     -MaskArgs @("-1","0123456789abcdefghijklmnopqrstuvwxyz","?1?1?1?1?1?1?1") `
            -OutLogName "hashcat_sha1_hard.txt"

Run-Hashcat -Mode 100 -HashFileName "sha1_veryhard.txt" -MaskArgs @("-1","0123456789abcdefghijklmnopqrstuvwxyz","?1?1?1?1?1?1?1?1") `
            -OutLogName "hashcat_sha1_veryhard.txt"


Run-Hashcat -Mode 3200 -HashFileName "bcrypt.txt"          -MaskArgs @("?d?d?d?d?d?d") `
            -OutLogName "hashcat_bcrypt_easy.txt"

Run-Hashcat -Mode 3200 -HashFileName "bcrypt_medium.txt"   -MaskArgs @("-1","0123456789abcdefghijklmnopqrstuvwxyz","?1?1?1?1?1?1") `
            -OutLogName "hashcat_bcrypt_medium.txt"

Run-Hashcat -Mode 3200 -HashFileName "bcrypt_hard.txt"     -MaskArgs @("-1","0123456789abcdefghijklmnopqrstuvwxyz","?1?1?1?1?1?1?1") `
            -OutLogName "hashcat_bcrypt_hard.txt"

Run-Hashcat -Mode 3200 -HashFileName "bcrypt_veryhard.txt" -MaskArgs @("-1","0123456789abcdefghijklmnopqrstuvwxyz","?1?1?1?1?1?1?1?1") `
            -OutLogName "hashcat_bcrypt_veryhard.txt"'''


$argonMode = 34000

'''Run-Hashcat -Mode $argonMode -HashFileName "argon2.txt"          -MaskArgs @("?d?d?d?d?d?d") `
            -OutLogName "hashcat_argon2_easy.txt"

Run-Hashcat -Mode $argonMode -HashFileName "argon2_medium.txt"   -MaskArgs @("-1","0123456789abcdefghijklmnopqrstuvwxyz","?1?1?1?1?1?1") `
            -OutLogName "hashcat_argon2_medium.txt"

Run-Hashcat -Mode $argonMode -HashFileName "argon2_hard.txt"     -MaskArgs @("-1","0123456789abcdefghijklmnopqrstuvwxyz","?1?1?1?1?1?1?1") `
            -OutLogName "hashcat_argon2_hard.txt"'''

Run-Hashcat -Mode $argonMode -HashFileName "argon2_veryhard.txt" -MaskArgs @("-1","0123456789abcdefghijklmnopqrstuvwxyz","?1?1?1?1?1?1?1?1") `
            -OutLogName "hashcat_argon2_veryhard.txt"

Write-Host ""
Write-Host "Готово. Логи hashcat_*.txt лежат в $hashFilesDir" -ForegroundColor Green
