# ADCFunctions.psm1
# Start with "Import-Module .\ADCFunctions.ps1" to use the functions in this module
# Version 0.1
# ADC SDX Nitro Functions

# Ignore Cert Errors and set TLS1.2
[System.Net.ServicePointManager]::CheckCertificateRevocationList = { $false }
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Set Extra Parameters in Powershell 6 and above
If ((get-host).version.Major -gt 5) {$params=@{SkipCertificateCheck = $true}} else {$params=@{}}

# Login to NetScaler and save session to global variable
function Login {
	[CmdLetBinding()]
	Param(	[Parameter(Mandatory=$true,ParameterSetName='Address')][string]$IP,
		[Parameter(Mandatory=$true)][string]$username,
		[Parameter(Mandatory=$true)][string]$password)
	$IPAddressObj = New-Object -TypeName System.Net.IPAddress -ArgumentList 0
	If (![System.Net.IPAddress]::TryParse($IP,[ref]$IPAddressObj) -or $IPAddressObj.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {throw "'$IP' is an invalid IPv4 address"}
	$Script:hostname = "https://$IP"
	$body = ConvertTo-JSON @{"login"=@{"username"="$username";"password"="$password"}}
	$R = Invoke-RestMethod -uri "$hostname/nitro/v2/config/login" -Method POST -body $body -SessionVariable NSSession -ContentType "application/json" @params
	$Script:NSSession = $local:NSSession
}

function Logout {
	CheckLogin
	$body = ConvertTo-JSON @{"logout"=@{}}
	$R = Invoke-RestMethod -uri "$hostname/nitro/v2/config/logout" -body $body -Method POST -WebSession $NSSession -ContentType "application/json" @params
}

# Get all VPX Instances that live on an SDX
function Get-VPXInstanceIDs{
	CheckLogin
	$R = Invoke-RestMethod -uri "$hostname/nitro/v2/config/ns" -Method GET -WebSession $NSSession -ContentType "application/json" @params
	$R.ns | select name, id | ft
}

# Get VPX Instance by name
function Get-VPXInstance($Name){
	CheckLogin
	$R = Invoke-RestMethod -uri "$hostname/nitro/v2/config/ns?filter=name:$Name" -Method GET -WebSession $NSSession -ContentType "application/json" @params
	$R.ns | fl
	$R.ns.network_interfaces | fl
}

# Get VPX Instance state by name
function Get-VPXInstanceState($Name){
	CheckLogin
	$R = Invoke-RestMethod -uri "$hostname/nitro/v2/config/ns?filter=name:$Name" -Method GET -WebSession $NSSession -ContentType "application/json" @params
	$R.ns.instance_state
}

# Remove VPX Instance by name
function Remove-VPXInstance($Name){
	CheckLogin
	$R = Invoke-RestMethod -uri "$hostname/nitro/v2/config/ns?filter=name:$Name" -Method GET -WebSession $NSSession -ContentType "application/json" @params
	$ID = $R.ns.id
	$R = Invoke-RestMethod -uri "$hostname/nitro/v2/config/ns/$ID" -Method DELETE -WebSession $NSSession -ContentType "application/json" @params
}

# Get VPX XEN Images that are available on the SDX
function Get-VPXImage {
	CheckLogin
	$R = Invoke-RestMethod -uri "$hostname/nitro/v2/config/xen_nsvpx_image" -Method GET -WebSession $NSSession -ContentType "application/json" @params
	$Images = $R.xen_nsvpx_image.file_name | Sort-Object -descending
	If ($Images.Count -eq 0) {Write-host "No VPX images found on SDX, please install XEN Bundle on SDX and try again" -ForegroundColor Red; Break}
	If ($Images.Count -eq 1) {$Script:Image = $Local:Images} else {$Script:Image = $Local:Images[0]}
}

# Create a VPX Instance
function Add-VPXInstance {
	[CmdLetBinding()]
	param(	[Parameter(Mandatory=$true)][string]$Name,
		[Parameter(Mandatory=$true,ParameterSetName='Address')][string]$IP,
		[Parameter(Mandatory=$true,ParameterSetName='Address')][string]$Subnetmask,
		[Parameter(Mandatory=$true,ParameterSetName='Address')][string]$Gateway,
		[Parameter(Mandatory=$true)][string]$AdminProfile,
		[Parameter(Mandatory=$true)][ValidateSet('standard','advanced','platinum')][string]$License,
		[Parameter(Mandatory=$true)][int]$Throughput,
		[Parameter()][int]$ACU,
		[Parameter()][int]$SCU,
		[Parameter(Mandatory=$true)][int]$Memory,
		[Parameter(Mandatory=$true)][ValidateRange(0,8)][int]$CPU,
		[Parameter()][switch]$L2=$false,
		[Parameter()][switch]$ManagementLA=$true,
		[Parameter()][ValidateRange(0,4096)][int]$ManagementVLAGTag,
		[Parameter()][string]$Interface1,
		[Parameter()][string]$Interface1VLANs,
		[Parameter()][string]$Interface2,
		[Parameter()][string]$Interface2VLANs,
		[Parameter()][string]$Interface3,
		[Parameter()][string]$Interface3VLANs,
		[Parameter()][switch]$NSVLANTAG=$false,
		[Parameter()][ValidateRange(0,4096)][int]$NSVLANID,
		[Parameter()][string]$NSVLANINTERFACES)
	CheckLogin

	$IPAddressObj = New-Object -TypeName System.Net.IPAddress -ArgumentList 0
	$SubnetMaskObj = New-Object -TypeName System.Net.IPAddress -ArgumentList 0
	If (![System.Net.IPAddress]::TryParse($IP,[ref]$IPAddressObj) -or $IPAddressObj.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {throw "'$IP' is an invalid IPv4 address"}
	If (![System.Net.IPAddress]::TryParse($SubnetMask,[ref]$SubnetMaskObj) -or $SubnetMaskObj.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {throw "'$SubnetMask' is an invalid IPv4 subnet mask"}
	If (![System.Net.IPAddress]::TryParse($Gateway,[ref]$IPAddressObj) -or $IPAddressObj.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {throw "'$Gateway' is an invalid IPv4 address"}

	$ns=@{"name"=$Name;"ip_address"=$IP;"netmask"=$Subnetmask;"gateway"=$Gateway;"profile_name"=$AdminProfile;"license"=$License;"throughput"=$Throughput;"vm_memory_total"=$Memory;"number_of_cores"=$CPU}

	Get-VPXImage
	Write-host "VPX will be provisioned with:" $Image -foregroundcolor green
	$ns.Add("image_name",$Image)

	If ($L2) {$ns.Add("l2_enabled","true")} else {$ns.Add("l2_enabled","false")}
	If ($ManagementLA) {$ns.Add("la_mgmt","true")} else {$ns.Add("la_mgmt","false")}
	If ($ACU) {$ns.Add("number_of_acu",$ACU)}
	If ($SCU) {$ns.Add("number_of_scu",$SCU)}
	If ($NSVLANTAG) {
		$ns.Add("nsvlan_tagged","true")
		If ($NSVLANID) {$ns.Add("nsvlan_id",$NSVLANID)}
		If (!([string]::IsNullOrEmpty($NSVLANINTERFACES))) {$ns.Add("nsvlan_interfaces_db",$NSVLANINTERFACES);$ns.Add("nsvlan_interfaces",@("$NSVLANINTERFACES"))}
	} else {$ns.Add("nsvlan_tagged","false")}

	$port1 = @{"port_name"="$Interface1"}
	If (!([string]::IsNullOrEmpty($Interface1VLANs))) {$port1.Add("vlan_whitelist",$Interface1VLANs);$port1.Add("vlan_whitelist_array",@("$Interface1VLANs"))}
	If (!([string]::IsNullOrEmpty($Interface2))) {$port2=@{};$port2.Add("port_name",$Interface2)}
	If (!([string]::IsNullOrEmpty($Interface2VLANs))) {$port2.Add("vlan_whitelist",$Interface2VLANs);$port2.Add("vlan_whitelist_array",@("$Interface2VLANs"))}
	If (!([string]::IsNullOrEmpty($Interface3))) {$port3=@{};$port3.Add("port_name",$Interface3)}
	If (!([string]::IsNullOrEmpty($Interface3VLANs))) {$port3.Add("vlan_whitelist",$Interface3VLANs);$port3.Add("vlan_whitelist_array",@("$Interface3VLANs"))}
	$net = @()
	$net +=, $port1
	If ($port2.count -gt 0) {$net +=, $port2}
	If ($port3.count -gt 0) {$net +=, $port3}
	$ns.Add("network_interfaces",$net)

	$body=@{"ns"=$ns}
	$json = ConvertTo-Json $Body -Depth 100
	$R = Invoke-RestMethod -uri "$hostname/nitro/v2/config/ns?action=add" -body $json -Method POST -WebSession $NSSession -ContentType "application/json" @params
	Write-Host "VPX $Name is created, waiting for VPX to become ready" -foregroundcolor yellow
	While ((Get-VPXInstanceState $Name) -ne "Up"){Start-Sleep 3;Write-Host . -NoNewline -foregroundcolor yellow}
	Write-Host "VPX $Name is up and running" -foregroundcolor green
}

# Check if the Login Function has run by checking the hostname variable
Function CheckLogin{If ($hostname -eq $NULL){Write-Host "Not logged in. Please login first" -foregroundcolor red;break}}