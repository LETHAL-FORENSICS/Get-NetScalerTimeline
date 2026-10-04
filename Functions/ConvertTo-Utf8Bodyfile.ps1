# ConvertTo-Utf8Bodyfile - Ensures a valid UTF-8 bodyfile (DuckDB rejects invalid UTF-8)
# UFS stores file names as raw bytes --> lines w/ invalid UTF-8 (e.g. Latin-1/Windows-1252 file names) are decoded as Latin-1, valid lines are kept as-is.
Function ConvertTo-Utf8Bodyfile
{
    Param(
        [Parameter(Mandatory = $true)]
        [String]$InFile,

        [Parameter(Mandatory = $true)]
        [String]$OutFile
    )

    $Strict = New-Object System.Text.UTF8Encoding($false, $true) # Throw on invalid bytes
    $Latin1 = [System.Text.Encoding]::GetEncoding(28591)         # Built-in in .NET Framework and .NET (Core)
    $Bytes  = [System.IO.File]::ReadAllBytes($InFile)
    $Writer = New-Object System.IO.StreamWriter($OutFile, $false, (New-Object System.Text.UTF8Encoding($false)))
    $Converted = 0

    try
    {
        $Start = 0
        while ($Start -lt $Bytes.Length)
        {
            $End = [Array]::IndexOf($Bytes, [byte]10, $Start)
            if ($End -lt 0) { $End = $Bytes.Length }

            try
            {
                $Line = $Strict.GetString($Bytes, $Start, $End - $Start)
            }
            catch
            {
                $Line = $Latin1.GetString($Bytes, $Start, $End - $Start)
                $Converted++
            }

            $Writer.Write($Line)
            $Writer.Write("`n")
            $Start = $End + 1
        }
    }
    finally
    {
        $Writer.Close()
    }

    $Converted
}