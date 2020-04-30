# frozen_string_literal: true

control 'V-1152' do
  title 'Anonymous access to the registry must be restricted.'
  desc  "The registry is integral to the function, security, and stability of
  the Windows system.  Some processes may require anonymous access to the
  registry.  This must be limited to properly protect the system."
  impact 0.7
  tag "gtitle": 'Anonymous Access to the Registry'
  tag "gid": 'V-1152'
  tag "rid": 'SV-52864r3_rule'
  tag "stig_id": 'WN12-RG-000004'
  tag "fix_id": 'F-80411r1_fix'
  tag "cci": ['CCI-002235']
  tag "nist": ['AC-6 (10)', 'Rev_4']
  tag "documentable": false
  tag "check": "Run \"Regedit\".
  Navigate to the following registry key:
  HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurePipeServers\\winreg\\

  If the key does not exist, this is a finding.

  Right-click on \"winreg\" and select \"Permissions…\".
  Select \"Advanced\".

  If the permissions are not as restrictive as the defaults listed below, this is
  a finding.

  The following are the same for each permission listed:
  Type - Allow
  Inherited from - None

  Columns: Principal - Access - Applies to
  Administrators - Full Control - This key and subkeys
  Backup Operators - Read - This key only
  LOCAL SERVICE - Read - This key and subkeys"
  tag "fix": "Maintain permissions at least as restrictive as the defaults
  listed below for the \"winreg\" registry key.  It is recommended to not change
  the permissions from the defaults.

  HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurePipeServers\\winreg\\

  The following are the same for each permission listed:
  Type - Allow
  Inherited from - None

  Columns: Principal - Access - Applies to
  Administrators - Full Control - This key and subkeys
  Backup Operators - Read - This key only
  LOCAL SERVICE - Read - This key and subkeys"

  hklm_winreg = <<-EOH
  $output = (Get-Acl -Path HKLM:System\\CurrentControlSet\\Control\\SecurePipeServers\\Winreg).AccessToString
  write-output $output
  EOH

  # raw powershell output
  raw_winreg = powershell(hklm_winreg).stdout.strip

  # clean results cleans up the extra line breaks
  clean_result_winreg = raw_winreg.lines.collect(&:strip)

  describe registry_key('HKLM\System\CurrentControlSet\Control\SecurePipeServers\Winreg') do
    it { should exist }
  end

  describe 'Verify the default registry permissions for the keys note below of the HKLM:System\\CurrentControlSet\\Control\\SecurePipeServers\\Winreg' do
    subject { clean_result_winreg }
    it { should be_in input('reg_winreg_perms') }
  end
  # describe windows_registry("HKLM:\\System\\CurrentControlSet\\Control\\SecurePipeServers\\Winreg") do
  # it { should be_allowed('read', by_user: 'NT AUTHORITY\\LOCAL SERVICE') }
  #  it { should be_allowed('full-control', by_user: 'BUILTIN\\Administrators') }
  #  it { should be_allowed('read', by_user: 'BUILTIN\\Backup Operators') }
  # end
end
