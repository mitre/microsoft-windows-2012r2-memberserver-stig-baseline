# frozen_string_literal: true

control 'V-26070' do
  title "Standard user accounts must only have Read permissions to the Winlogon
  registry key."
  desc "Permissions on the Winlogon registry key must only allow privileged
  accounts to change registry values.  If standard users have these permissions,
  there is a potential for programs to run with elevated privileges when a
  privileged user logs on to the system."
  impact 0.7
  tag "gtitle": 'Winlogon Registry Permissions'
  tag "gid": 'V-26070'
  tag "rid": 'SV-53123r4_rule'
  tag "stig_id": 'WN12-RG-000001'
  tag "fix_id": 'F-80413r1_fix'
  tag "cci": ['CCI-002235']
  tag "nist": ['AC-6 (10)', 'Rev_4']
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

  hklm_winlogon = <<-EOH
  $output = (Get-Acl -Path 'HKLM:\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon').AccessToString
  write-output $output
  EOH

  # raw powershell output
  raw_winlogon = powershell(hklm_winlogon).stdout.strip

  # clean results cleans up the extra line breaks
  clean_winlogon = raw_winlogon.lines.collect(&:strip)

  describe 'Verify the default registry permissions for the keys note below of the HKLM:\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' do
    subject { clean_winlogon }
    it { should cmp input('reg_winlogon_perms') }
  end
end
