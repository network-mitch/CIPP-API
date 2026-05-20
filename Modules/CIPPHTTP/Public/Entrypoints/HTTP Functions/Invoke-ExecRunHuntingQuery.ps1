Function Invoke-ExecRunHuntingQuery {
	<#
	.FUNCTIONALITY
		Entrypoint

	.ROLE
		Security.Alert.ReadWrite

	.SYNOPSIS
		POST passthrough for Microsoft Graph runHuntingQuery.

	.DESCRIPTION
		Executes a Microsoft 365 Defender Advanced Hunting (KQL) query against
		a customer tenant via Graph beta /security/runHuntingQuery

	.PARAMETER Request
		Azure Functions HTTP request context. Expected body shape:
			{
			  "TenantFilter": "<customer tenant id GUID or default domain>",
			  "Query":        "<KQL query string>"
			}

	.OUTPUTS
		JSON response with the Graph response passed through verbatim:
			{
			  "schema":  [ { "Name": "Timestamp", "Type": "DateTime" }, ... ],
			  "results": [ { ... }, ... ]
			}

		On error: HTTP 400 with { "error": "<message>" }.
	#>

    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $APIName = $Request.Params.CIPPEndpoint
    $Headers = $Request.Headers
    Write-LogMessage -headers $Headers -API $APIName -message 'Accessed this API' -Sev 'Debug'

    # --- Input validation -------------------------------------------------
    $TenantFilter = $Request.Body.TenantFilter
    $Query        = $Request.Body.Query

    if ([string]::IsNullOrWhiteSpace($TenantFilter)) {
        Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::BadRequest
            Body       = @{ error = "TenantFilter is required in the request body." }
        })
        return
    }
    if ([string]::IsNullOrWhiteSpace($Query)) {
        Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::BadRequest
            Body       = @{ error = "Query is required in the request body." }
        })
        return
    }

    $GraphBody = @{ Query = $Query } | ConvertTo-Json -Compress -Depth 5

    try {
        $Result = New-GraphPOSTRequest `
            -uri 'https://graph.microsoft.com/v1.0/security/runHuntingQuery' `
            -tenantid $TenantFilter `
            -body $GraphBody `
            -AsApp $true `
            -type 'POST'

        $Body = @{
            schema  = $Result.schema
            results = $Result.results
        }
        if ($Result.PSObject.Properties['stats']) { $Body.stats = $Result.stats }

        Write-LogMessage -headers $Headers -API $APIName `
            -message ("runHuntingQuery succeeded for tenant {0}: {1} rows" -f $TenantFilter, ($Result.results | Measure-Object).Count) `
            -Sev 'Info' -tenant $TenantFilter

        Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::OK
            Body       = $Body
        })
        return
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Headers -API $APIName `
            -message ("runHuntingQuery failed for tenant {0}: {1}" -f $TenantFilter, $ErrorMessage.NormalizedError) `
            -Sev 'Error' -tenant $TenantFilter -LogData $ErrorMessage

        Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::BadRequest
            Body       = @{ error = $ErrorMessage.NormalizedError }
        })
        return
    }
}
