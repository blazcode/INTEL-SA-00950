#  Host Redundant Prefix Issue Check for vCenter Hosts

The purpose of this script is to assist determining if VMware vCenter managed hosts have Intel processors affected by INTEL-SA-00950\CVE-2023-23583.

Hypervisor patches are not required to resolve the vulnerability. Contact hardware vendors for a firmware update for affected CPU if one is not already available.

### Interpreting script output:
Affected = Obtain and install firmware update from hardware vendor ASAP if microcode is below mitigated version! Reference Intel documenation for details.

Not Affected = Host CPU is not affected by CVE-2023-23583, no action is required.

Mitigated = Host CPU has already mitigated microcode, no action is required.

### Prerequisites:
https://developer.vmware.com/web/tool/13.1.0/vmware-powercli/

### References:
https://blogs.vmware.com/security/2023/11/cve-2023-23583.html

https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00950.html

https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/advisory-guidance/redundant-prefix-issue.html
