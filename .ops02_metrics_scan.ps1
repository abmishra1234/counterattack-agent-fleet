$ErrorActionPreference = 'Stop'
$response = Invoke-WebRequest -Uri 'http://127.0.0.1:8000/metrics' -TimeoutSec 15 -UseBasicParsing
if ($response.StatusCode -ne 200) { throw "Metrics scrape returned HTTP $($response.StatusCode)." }
$body = [string]$response.Content
foreach ($required in @('counterstrike_http_requests_total', 'counterstrike_http_request_duration_seconds', 'counterstrike_jobs', 'counterstrike_llm_calls', 'counterstrike_database_up 1')) {
    if (-not $body.Contains($required)) { throw "Expected metrics output is missing '$required'." }
}
if ($body -match 'CVE-[0-9]{4}-[0-9]+' -or $body -match '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}' -or $body -match 'prompt_hash|actor_id|advisory_id|asset_id|model=') {
    throw 'A high-cardinality or sensitive identifier appeared in metrics output.'
}
$allowedLabelKeys = @('method', 'route', 'status', 'le', 'direction', 'outcome', 'status')
foreach ($line in ($body -split "`n" | Where-Object { $_ -match '^counterstrike_http_' -and $_ -match '\{' })) {
    $labelText = [regex]::Match($line, '\{([^}]*)\}').Groups[1].Value
    foreach ($label in ($labelText -split ',')) {
        $name = ($label -split '=', 2)[0]
        if ($name -notin $allowedLabelKeys) { throw "Unexpected HTTP metric label '$name'." }
    }
}
Write-Output (@{ status = $response.StatusCode; low_cardinality_label_scan = 'passed'; database_up = $body.Contains('counterstrike_database_up 1') } | ConvertTo-Json -Compress)
