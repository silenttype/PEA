Try{
		
	$Utf8NoBomEncoding = New-Object System.Text.UTF8Encoding $False
	$txt4104 = Get-WinEvent -Oldest -ErrorAction Stop -FilterHashtable @{logname='Microsoft-Windows-PowerShell/Operational'; StartTime=(Get-Date).date; ID=4104} | Where-Object -Property Message -NotMatch 'EventExtractor.ps1' | ConvertTo-Json
	$txt4103 = Get-WinEvent -Oldest -ErrorAction Stop -FilterHashtable @{logname='Microsoft-Windows-PowerShell/Operational'; StartTime=(Get-Date).date; ID=4103} | Where-Object -Property Message -NotMatch 'EventExtractor.ps1' | %{write-output $_.Message}
	[System.IO.File]::WriteAllLines($PSScriptRoot + "\4104.txt", $txt4104, $Utf8NoBomEncoding)
	[System.IO.File]::WriteAllLines($PSScriptRoot + "\4103.txt", $txt4103, $Utf8NoBomEncoding)
}
catch [Exception] 
{
	if ($_.Exception -match "No events were found that match the specified selection criteria.") {
		Write-Output "No events found";
    }
}
