control "V-1152" do
  title "Anonymous access to the registry must be restricted."
  desc  "The registry is integral to the function, security, and stability of
  the Windows system.  Some processes may require anonymous access to the
  registry.  This must be limited to properly protect the system."
  impact 0.7
  tag "gtitle": "Anonymous Access to the Registry"
  tag "gid": "V-1152"
  tag "rid": "SV-52864r3_rule"
  tag "stig_id": "WN12-RG-000004"
  tag "fix_id": "F-80411r1_fix"
  tag "cci": ["CCI-002235"]
  tag "nist": ["CCI-002235"]
  tag "nist": ["AC-6 (10)", "Rev_4"]
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
  describe command('Get-Acl -Path "HKLM:\\System\\CurrentControlSet\\Control\\SecurePipeServers\\Winreg" | Format-List | Findstr All | Findstr /V 2') do
   its('stdout') { should eq "         NT AUTHORITY\\LOCAL SERVICE Allow  ReadKey\r\n         BUILTIN\\Administrators Allow  FullControl\r\n         BUILTIN\\Backup Operators Allow  ReadKey\r\n" }
  end
  describe registry_key('HKLM\System\CurrentControlSet\Control\SecurePipeServers\Winreg') do
    it { should exist }
  end

end

 