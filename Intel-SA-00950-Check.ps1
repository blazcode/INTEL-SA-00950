# vCenter Host Redundant Prefix Issue Check
#
# CVE-2023-23583
# INTEL-SA-00950
#
# The purpose of this script is to assist determining if VMware vCenter managed hosts have Intel processors affected by CVE-2023-23583.
#
# Hypervisor patches are not required to resolve the vulnerability. Contact hardware vendors for a firmware update for affected CPU if one is not already available.
#
# Interpreting script output:
# Affected = Obtain and install firmware update from hardware vendor ASAP if microcode is below mitigated version! Reference Intel documenation for details.
# Not Affected = Host CPU is not affected by CVE-2023-23583, no action is required.
# Mitigated = Host CPU has already mitigated microcode, no action is required.
#
# Prerequisites:
# https://developer.vmware.com/web/tool/13.1.0/vmware-powercli/
#
# References:
# https://blogs.vmware.com/security/2023/11/cve-2023-23583.html
# https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00950.html
# https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/advisory-guidance/redundant-prefix-issue.html

# ----------------------------------
#     Configuration
# ----------------------------------

# vCenter fully qualified domain name, i.e. "vcenter.corp.local"
$vCenter = "vcsa-8x.corp.local"

# Path to export .csv report, i.e. "C:\Users\Administrator\Desktop"
$reportPath = "C:\Users\Administrator\Desktop\"

# ----------------------------------

function Convert-EaxToHex {
    param (
        [string]$binaryString
    )

    # Remove colons (:) if present in the binary string
    $binaryString = $binaryString -replace ":", ""

    # Convert binary string to hexadecimal
    $hexString = [Convert]::ToString([Convert]::ToInt32($binaryString, 2), 16).ToUpper()

    # Return the hexadecimal string
    return "$hexString"
}

Import-Module VMware.PowerCLI

Connect-VIServer -Server $vCenter -Credential $(Get-Credential) -Force

#Reference: https://www.intel.com/content/www/us/en/developer/topic-technology/software-security-guidance/processors-affected-consolidated-product-cpu-model.html
$affectedCpuIds = @(
    "706E5", # 10th Generation Intel® Core™ Processor Family
    "606A6", # 3rd Gen Intel® Xeon® Scalable processor family
    "606C1", # Intel® Xeon® D Processor
    "A0671", # 11th Generation Intel® Core™ Processor Family, Intel® Xeon® E-2300 Processor Family, Intel® Xeon® W-1300 processor family
    "806C1", # 11th Generation Intel® Core™ Processor Family
    "806C2", # 11th Generation Intel® Core™ Processor Family
    "806D1", # 11th Generation Intel® Core™ Processor Family, Intel® Xeon® Processor Family
    "A0671", # 11th Generation Intel® Core™ Processor Family, Intel® Xeon® E-2300 Processor Family, Intel® Xeon® W-1300 processor family
    "806F7", # 4th Generation Intel® Xeon® Scalable processors, 4th Generation Intel® Xeon® Platinum processors, 4th Generation Intel® Xeon® Gold Processors, 4th Generation Intel® Xeon® Silver Processor, 4th Generation Intel® Xeon®Bronze Processor, 4th Gen Intel Xeon Scalable Processors with Intel® vRAN, Intel® Xeon® W workstation processors
    "806F8", # 4th Generation Intel® Xeon® Scalable processors, 4th Generation Intel® Xeon® Platinum processors, 4th Generation Intel® Xeon® Gold Processors, 4th Generation Intel® Xeon® Silver Processor, 4th Generation Intel® Xeon®Bronze Processor, 4th Gen Intel Xeon Scalable Processors with Intel® vRAN, Intel® Xeon® W workstation processors
    "90672", # 12th Generation Intel® Core™ Processor Family
    "90675", # 12th Generation Intel® Core™ Processor Family, Intel® Pentium® Gold Processor Family, Intel® Celeron® Processor Family
    "906A3", # 12th Generation Intel® Core™ Processor Family, 12th Generation Intel® Core™ Processor Family
    "906A4", # 12th Generation Intel® Core™ Processor Family, Intel® Pentium® Gold Processor Family, Intel® Celeron® Processor Family
    "B06A2", # 13th Generation Intel® Core™ Processor Family, Intel® Processor U-series
    "B06A3", # 13th Generation Intel® Core™ Processor Family, Intel® Processor U-series
    "B06F2", # 13th Generation Intel® Core™ Processor Family, Intel® Processor U-series
    "B06F5"  # 13th Generation Intel® Core™ Processor Family, Intel® Processor U-series
)

#Reference: https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00950.html
$mitigatedCpuIds = @(
    "906A4", # 12th Generation Intel® Core™ Processor Family
    "B0671"  # 13th Generation Intel® Core™ Processor Family
)

$vmHostInfo = @()
$vmHosts = Get-VMHost

foreach ($vmHost in $vmHosts) {
    $intelSa00950 = "Not Affected - no action required."

    # Get host CPUID
    $vmHostCpuId = Convert-EaxToHex($vmHost.ExtensionData.Hardware.CpuPkg[0].CpuFeature[1].Eax)

    # Compare host CPUID with affected CPUIDs
    foreach ($affectedCpuId in $affectedCpuIds){
        if ($vmHostCpuId -eq $affectedCpuId) {
            $cpuId = $affectedCpuId
            $intelSa00950 = "Affected - Obtain and isntall firmware update from hardware vendor ASAP if microcode is bleow mitigated version!"
        }
    }

    # Compare host CPUID with mitigated CPUIDs
    foreach ($mitigatedCpuId in $mitigatedCpuIds){      
        if ($vmHostCpuId -eq $mitigatedCpuId) {
            $cpuId = $mitigatedCpuId
            $intelSa00950 = "Mitigated - No action required."
        }
    }
      
    $vmHostDetails = [PSCustomObject]@{
        "Hostname" = $vmHost.Name
        "CPU" = $vmHost.ExtensionData.Hardware.CpuPkg[0].Description
        "CPUID" = $cpuId
        "Intel-SA-00950" = $intelSa00950
    }
    
    $vmHostInfo += $vmHostDetails
}

$vmHostInfo

# Export Report
$vmHostInfo | Export-Csv -Path $($reportPath.TrimEnd('\') + "\Intel-SA-00950 Report.csv") -NoTypeInformation

Disconnect-VIServer -Confirm:$false
