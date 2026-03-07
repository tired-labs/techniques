#Based on a script from https://learn.microsoft.com/en-us/troubleshoot/windows-server/support-tools/script-to-view-msds-keycredentiallink-attribute-value
#Modified to include information about key creation date and FIDO cert info.

$KCLs = @() #Array to hold all KCL entries found

# Enumerate all AD users that have an msds-KeyCredentialLink value
foreach ($user in (Get-ADUser -LDAPFilter '(msDS-KeyCredentialLink=*)' -Properties "msDS-KeyCredentialLink")) {

    foreach ($blob in ($user."msDS-KeyCredentialLink")) {
        #create custom object to store KCL information
        $KCLEntry = [PSCustomObject]@{
            User       = $null
            DistinguishedName = $null
            KeyID = $null
            Usage = $null
            KeyMaterial = $null
            Source = $null
            DeviceID = $null
            DisplayName = $null
            Cert = $null
            CertIssuer = $null
            CertSubject = $null
            LastLogon = $null
            CreationDate = $null
        }
    
        # For each user, get the UPN, DN
        $KCLEntry.User = $user.UserPrincipalName
        $KCLEntry.DistinguishedName = $user.DistinguishedName 
        
        $KCLstring = ($blob -split ':')[2]

        # Check that the entries are version 2
        if ($KCLstring.Substring(0, 8) -eq "00020000") {
            $curIndex = 8   
            
            # Parse all KeyCredentialLink entries from the hex string
            while ($curIndex -lt $KCLstring.Length) {
            
                # Read the length, reverse the byte order to account for endianess, then convert to an int
                # The length is in bytes, so multiply by 2 to get the length in characters
                $strLength = ($KCLstring.Substring($curIndex, 4)) -split '(?<=\G..)(?!$)'
                [array]::Reverse($strLength)
                $kcle_Length = ([convert]::ToInt16(-join $strLength, 16)) * 2
            
                # Read the identifier and value
                $kcle_Identifier = $KCLstring.Substring($curIndex + 4, 2)
                $kcle_Value = $KCLstring.Substring($curIndex + 6, $kcle_Length)

                switch ($kcle_Identifier) {
                    # KeyID 
                    '01' {
                        $KCLEntry.KeyID = $kcle_Value
                    }

                    # KeyMaterial 
                    '03' {
                        $KCLEntry.KeyMaterial = $kcle_Value
                    }
                    
                    # KeyUsage
                    '04' {
                        switch ($kcle_Value) {
                            '00' { $KCLEntry.Usage = "Admin (PIN reset key)" }
                            '01' { $KCLEntry.Usage = "Next-Gen Cred (Hello)" }
                            '02' { $KCLEntry.Usage = "Session Transport Key" }
                            '03' { $KCLEntry.Usage = "BitLocker Recovery" }
                            '07' { $KCLEntry.Usage = "FIDO" }
                            '08' { $KCLEntry.Usage = "File Encryption Key" }
                            Default { $Usage = $KCLEntry.kcle_Value }
                        }
                    }

                    # Source
                    '05' {
                        switch ($kcle_Value) {
                            '00' { $KCLEntry.Source = "AD" }
                            '01' { $KCLEntry.Source = "Entra" }
                            Default { $KCLEntry.Source = $kcle_Value }
                        }
                    }
                    
                    # DeviceID
                    '06' {
                        $tempByteArray = $kcle_Value -split '(?<=\G..)(?!$)'
                        $KCLEntry.DeviceID = [System.Guid]::new($tempByteArray[3..0] + $tempByteArray[5..4] + $tempByteArray[7..6] + $tempByteArray[8..16] -join "")
                    }

                    # KeyApproximateLastLogonTimeStamp 
                    '08' {
                        #convert the hex string to a byte array
                        [byte[]]$byteArray = ($kcle_Value -replace '..', '0x$& ' -split ' ' -ne '')
                        #convert the byte array to an Int64
                        $Int64 = [System.BitConverter]::ToInt64($byteArray, 0)
                        
                        #AD uses a FILETIME timestamp format, while Entra uses a binary timestamp format
                        if ($KCLEntry.Source -eq 'AD') { 
                           $KCLEntry.LastLogon = [System.DateTime]::FromFileTime($Int64)
                        }
                        else { 
                           $KCLEntry.LastLogon = [System.DateTime]::FromBinary($Int64)
                        }
                    }

                    # KeyCreationTime
                    '09' {
                        #convert the hex string to a byte array
                        [byte[]]$byteArray = ($kcle_Value -replace '..', '0x$& ' -split ' ' -ne '')
                        #convert the byte array to an Int64
                        $Int64 = [System.BitConverter]::ToInt64($byteArray, 0)
                        
                            #AD uses a FILETIME timestamp format, while Entra uses a binary timestamp format
                        if ($KCLEntry.Source -eq 'AD') { 
                            $KCLEntry.CreationDate = [System.DateTime]::FromFileTime($Int64)
                        }
                        else { 
                            $KCLEntry.CreationDate = [System.DateTime]::FromBinary($Int64)
                        }
                    }
                }

                $curIndex += 6 + $kcle_Length
            }

            # if FIDO, get additional details about the certificate issuer, subject, and the display name used when creating it
            # NGC and FKE only have the RSA public key, so little useful to display
            if ($KCLEntry.Usage -eq 'FIDO') {
                #convert hex string to ASCII string, then to JSON object
                $jsonObject = ($KCLEntry.KeyMaterial -split '(..)' | Where-Object { -not [string]::IsNullOrEmpty($_) } | ForEach-Object { [char][convert]::ToInt32($_, 16) }) -join "" | ConvertFrom-Json

                $KCLEntry.DisplayName = $jsonObject.displayName
                $KCLEntry.Cert = [X509Certificate]::new([convert]::FromBase64String($jsonObject.x5c))
                $KCLEntry.CertIssuer = $Cert.Issuer
                $KCLEntry.CertSubject = $Cert.Subject
            } 
        }
        $KCLs += $KCLEntry  #Add current entry to array
    }
}

# Each full KCL object is stored in the $KCL array, so you can modify this line to change what is included in the output.
Write-Output $KCLs | Format-Table -AutoSize -Property User, Source, Usage, CreationDate, DisplayName, CertIssuer, DeviceId, KeyID | out-file ./KCL_Report.txt
