control "V-32282" do
  title "Standard user accounts must only have Read permissions to the Active
  Setup\\Installed Components registry key."
  desc  "Permissions on the Active Setup\\Installed Components registry key
  must only allow privileged accounts to add or change registry values.  If
  standard user accounts have these permissions, there is a potential for
  programs to run with elevated privileges when a privileged user logs on to the
  system."
  impact 0.7
  tag "gtitle": "WINRG-000001 Active Setup\\Installed Components Registry
  Permissions"
  tag "gid": "V-32282"
  tag "rid": "SV-52956r3_rule"
  tag "stig_id": "WN12-RG-000002"
  tag "fix_id": "F-71731r1_fix"
  tag "cci": ["CCI-002235"]
  tag "nist": ["CCI-002235"]
  tag "nist": ["AC-6 (10)", "Rev_4"]
  tag "documentable": false
  tag "check": "Run \"Regedit\".
  Navigate to the following registry keys and review the permissions:
  HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Active Setup\\Installed Components\\
  HKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432Node\\Microsoft\\Active Setup\\Installed
  Components\\ (64-bit systems)

  If the default permissions listed below have been changed, this is a finding.

  Users - Read
  Administrators - Full Control
  SYSTEM - Full Control
  CREATOR OWNER - Full Control (Subkeys only)
  ALL APPLICATION PACKAGES - Read"
  tag "fix": "Maintain the default permissions of the following registry keys:
  HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Active Setup\\Installed Components\\
  HKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432Node\\Microsoft\\Active Setup\\Installed
  Components\\ (64-bit systems only)

  Users - Read
  Administrators - Full Control
  SYSTEM - Full Control
  CREATOR OWNER - Full Control (Subkeys only)
  ALL APPLICATION PACKAGES - Read"
  
  describe command('Get-Acl -Path "HKLM:\\Software\\Microsoft\\Active Setup\\Installed Components\\" | Format-List | Findstr All | Findstr /V 2') do
    its('stdout') { should eq "         BUILTIN\\Users Allow  ReadKey\r\n         BUILTIN\\Administrators Allow  FullControl\r\n         NT AUTHORITY\\SYSTEM Allow  FullControl\r\n         APPLICATION PACKAGE AUTHORITY\\ALL APPLICATION PACKAGES Allow  ReadKey\r\n" }
  end

  describe command('Get-Acl -Path "HKLM:\\Software\\Microsoft\\Active Setup\\Installed Components\\" | Format-List | Findstr All | Findstr CREATOR') do
    its('stdout') { should eq "         CREATOR OWNER Allow  268435456\r\n" }
  end

  describe command('Get-Acl -Path "HKLM:\\Software\\Wow6432Node\\Microsoft\\Active Setup\\Installed Components\\" | Format-List | Findstr All | Findstr /V 2') do
    its('stdout') { should eq "Access : BUILTIN\\Users Allow  ReadKey\r\n         BUILTIN\\Administrators Allow  FullControl\r\n         NT AUTHORITY\\SYSTEM Allow  FullControl\r\n         APPLICATION PACKAGE AUTHORITY\\ALL APPLICATION PACKAGES Allow  ReadKey\r\n" }
  end
  
  describe command('Get-Acl -Path "HKLM:\\Software\\Wow6432Node\\Microsoft\\Active Setup\\Installed Components\\" | Format-List | Findstr All | Findstr CREATOR') do
    its('stdout') { should eq "         CREATOR OWNER Allow  268435456\r\n" }
  end

end

  

 