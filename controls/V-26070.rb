control "V-26070" do
  title "Standard user accounts must only have Read permissions to the Winlogon
  registry key."
  desc  "Permissions on the Winlogon registry key must only allow privileged
  accounts to change registry values.  If standard users have these permissions,
  there is a potential for programs to run with elevated privileges when a
  privileged user logs on to the system."
  impact 0.7
  tag "gtitle": "Winlogon Registry Permissions"
  tag "gid": "V-26070"
  tag "rid": "SV-53123r4_rule"
  tag "stig_id": "WN12-RG-000001"
  tag "fix_id": "F-80413r1_fix"
  tag "cci": ["CCI-002235"]
  tag "nist": ["AC-6 (10)", "Rev_4"]
  tag "documentable": false
  tag "check": "Run \"Regedit\".
  Navigate to the following registry key:
  HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\

  Right-click on \"WinLogon\" and select \"Permissions…\".
  Select \"Advanced\".

  If the permissions are not as restrictive as the defaults listed below, this is
  a finding.

  The following are the same for each permission listed:
  Type - Allow
  Inherited from - MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion
  Applies to - This key and subkeys

  Columns: Principal - Access
  TrustedInstaller - Full Control
  SYSTEM - Full Control
  Administrators - Full Control
  Users - Read
  ALL APPLICATION PACKAGES - Read"
  tag "fix": "Maintain permissions at least as restrictive as the defaults
  listed below for the \"WinLogon\" registry key.  It is recommended to not
  change the permissions from the defaults.

  HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\

  The following are the same for each permission listed:
  Type - Allow
  Inherited from - MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion
  Applies to - This key and subkeys

  Columns: Principal - Access
  TrustedInstaller - Full Control
  SYSTEM - Full Control
  Administrators - Full Control
  Users - Read
  ALL APPLICATION PACKAGES - Read"
  describe command('Get-Acl -Path "HKLM:\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" | Format-List | Findstr All') do
   its('stdout') { should eq "Access : NT AUTHORITY\\SYSTEM Allow  FullControl\r\n         BUILTIN\\Administrators Allow  FullControl\r\n         BUILTIN\\Users Allow  ReadKey\r\n         NT SERVICE\\TrustedInstaller Allow  FullControl\r\n         APPLICATION PACKAGE AUTHORITY\\ALL APPLICATION PACKAGES Allow  ReadKey\r\n" }
  end
end








