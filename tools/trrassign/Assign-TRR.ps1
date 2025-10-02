function Assign-TRR {
    param (
        [Parameter(Mandatory=$false)][String]$oldTrrID,
        [Parameter(Mandatory=$false)][String]$newTrrID,
        [Parameter(Mandatory=$true)][String]$reportFolder
    )
    
        $trrRegex = "(?-i)TRR[0-9]{4}"
    
        if ($PSCmdlet.MyInvocation.BoundParameters.Count -eq 0) {
            $oldTrrIdUpper = "TRR0000"
            $oldTrrIdLower = $oldTrrIdUpper.ToLower()
        } elseif ([String]::IsNullOrEmpty($oldTrrID)) {
            Write-Output "Missing Old TRR ID"
            return
        } elseif ([String]::IsNullOrEmpty($newTrrID)) {
            Write-Output "Missing New TRR ID"
            return
        } else {
            $oldTrrIdUpper = $oldTrrID.ToUpper()
            $oldTrrIdLower = $oldTrrID.ToLower()
            $newTrrIdUpper = $newTrrID.ToUpper()
            $newTrrIdLower = $newTrrID.ToLower()
        }
    
        if ([String]::IsNullOrEmpty($newTrrID)) {
            $jsonString = Get-Content -Raw .\index.json
            $jsonObj = ConvertFrom-Json $jsonString
            $lastTrrNumber = [int]($jsonObj[-1].id).Substring(3)
            Write-Output "Last number assigned is: $lastTrrNumber"
            $newTrrNumber = [int]($jsonObj[-1].id).Substring(3) + 1
            Write-Output "Next available number is: $newTrrNumber"
            $newTrrID = "TRR" + $newTrrNumber.ToString().PadLeft(4, '0')
            $newTrrIdUpper = $newTrrID.ToUpper()
            $newTrrIdLower = $newTrrID.ToLower()
        }
    
        if (($newTrrIdUpper -notmatch $trrRegex) -or ($oldTrrIdUpper -notmatch $trrRegex)){
            Write-Output "Error: invalid TRR number while trying to assign $oldTrrID to $newTrrID."
            return
        }
    
        if ([String]::IsNullOrEmpty($reportFolder)) {
            Write-Output "Missing TRR folder"
            return
        }

        if (-not(Test-Path -path $reportFolder)) {
            Write-Output "TRR folder doesn't exist: $reportFolder"
            return
        }

        $reportFolderObj = Get-Item $reportFolder
        if (-not($reportFolderObj.PSIsContainer)) {
            Write-Output "Specified TRR folder is not a folder: $reportFolder"
            return
        }
    
        $trrFiles = @(
          "$($reportFolderObj.FullName)\$oldTrrIdLower\*\README.md"
          "$($reportFolderObj.FullName)\$oldTrrIdLower\*\metadata.json"
        )
    
        Write-Output "TRR Number assignment script - assigning $oldTrrIdUpper to $newTrrIdUpper."

        foreach ($filename in $trrFiles){
          (Get-Content $filename).Replace("$oldTrrIdLower", "$newTrrIdLower") | Set-Content $filename
          (Get-Content $filename).Replace("$oldTrrIdUpper", "$newTrrIdUpper") | Set-Content $filename
        }
    
        foreach ($filename in $(Get-ChildItem -ErrorAction Stop -Recurse "..\..\reports\$oldTrrIdLower")){
            if ($filename.PSIsContainer){
                $parentDirectory = $filename.Parent.FullName.Replace($oldTrrIdLower, $newTrrIdLower)
                $newFilename = $parentDirectory + "\" + $filename.Name.Replace($oldTrrIdLower, $newTrrIdLower)
                New-Item -Type Directory -Force $newFilename | Out-Null
            } else {
                $oldFilename = $filename.FullName
                $newFilename = $filename.FullName.Replace($oldTrrIdLower, $newTrrIdLower)
                Move-Item "$oldFilename" "$newFilename" | Out-Null
            }
        }
        
        Remove-Item -Recurse "$($reportFolderObj.FullName)\$oldTrrID"
        Write-Output "Reassignment complete."
    }