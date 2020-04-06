control 'V-34974' do
  title "The Windows Installer Always install with elevated privileges option
  must be disabled."
  desc "Standard user accounts must not be granted elevated privileges.
  Enabling Windows Installer to elevate privileges when installing applications
  can allow malicious persons and applications to gain full control of a system."
  impact 0.7
  tag "gtitle": 'Always Install with Elevated Privileges Disabled'
  tag "gid": 'V-34974'
  tag "rid": 'SV-52954r1_rule'
  tag "stig_id": 'WN12-CC-000116'
  tag "fix_id": 'F-45880r1_fix'
  tag "cci": ['CCI-001812']
  tag "cce": ['CCE-23919-4']
  tag "nist": ['CM-11 (2)', 'Rev_4']
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\Software\\Policies\\Microsoft\\Windows\\Installer\\

  Value Name: AlwaysInstallElevated

  Type: REG_DWORD
  Value: 0"
  tag "fix": "Configure the policy value for Computer Configuration ->
  Administrative Templates -> Windows Components -> Windows Installer -> \"Always
  install with elevated privileges\" to \"Disabled\"."
  
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Installer') do
    it { should have_property 'AlwaysInstallElevated' }
    its('AlwaysInstallElevated') { should cmp == 0 }
  end
end
