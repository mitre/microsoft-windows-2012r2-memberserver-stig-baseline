control 'V-80475' do
 title "PowerShell script block logging must be enabled on Windows 2012/2012 R2"
 desc "Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze 
 compromises that have occurred, as well as detect attacks. Audit logs are necessary to provide a trail of evidence in case the system or network is 
 compromised. Collecting this data is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.

Enabling PowerShell script block logging will record detailed information from the processing of PowerShell commands and scripts. This can provide additional 
detail when malware has run on a system.

PowerShell 5.x supports script block logging. PowerShell 4.0 with the addition of patch KB3000850 on Windows 2012 R2 or KB3119938 on Windows 2012 adds support for 
script block logging."
 impact 0.5
 tag "gtitle": 'WIN00-000210'
 tag "gid": 'V-80475'
 tag "rid": 'SV-95183r2_rule'
 tag "stig_id": 'WN12-00-000210'
 tag "fix_id": '_fix'
 tag "cci": ['CCI-000135']
 tag "nist": ['AU-3 (1)', 'AU-3 (1).1 (ii)', 'Rev_4']
 tag "documentable": false
 tag "check": "If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging\

Value Name: EnableScriptBlockLogging

Value Type: REG_DWORD
Value: 0x00000001 (1)

PowerShell 4.0 requires the installation of patch KB3000850 on Windows 2012 R2 or KB3119938 on Windows 2012. 

If the patch is not installed on systems with PowerShell 4.0, this is a finding.

PowerShell 5.x does not require the installation of an additional patch."
tag "fix": "Configure the following registry value as specified.

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging\

Value Name: EnableScriptBlockLogging

Value Type: REG_DWORD
Value: 0x00000001 (1)

Administrative templates from later versions of Windows include a group policy setting for this. Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Windows PowerShell >> "Turn on PowerShell Script Block Logging" to "Enabled". 

Install patch KB3000850 on Windows 2012 R2 or KB3119938 on Windows 2012 on systems with PowerShell 4.0. 

PowerShell 5.x does not require the installation of an additional patch."

powershell_version = json({ command: '$PSVersionTable.PSVersion | Select Major | ConvertTo-Json' } )
version_check = powershell_version["Major"]

if (version_check >= 5)
 #impact 0.0
 describe 'PowerShell 5.x is installed and does not require patch' do
  skip 'PowerShell 5.x is installed and does not require patch'
  end
else
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging") do
    it { should have_property 'EnableScriptBlockLogging' } 
    its('EnableScriptBlockLogging') { should cmp == 1 }
  end
 end
end