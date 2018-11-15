control "V-15701" do
  title "A system restore point must be created when a new device driver is
  installed."
  desc  "A system restore point allows a rollback if an issue is encountered
  when a new device driver is installed."
  impact 0.3
  tag "gtitle": "Device Install – Drivers System Restore Point"
  tag "gid": "V-15701"
  tag "rid": "SV-53099r1_rule"
  tag "stig_id": "WN12-CC-000021"
  tag "fix_id": "F-46025r1_fix"
  tag "cci": ["CCI-000366"]
  tag "cce": ["CCE-23669-5"]
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path:
  \\Software\\Policies\\Microsoft\\Windows\\DeviceInstall\\Settings\\

  Value Name: DisableSystemRestore

  Type: REG_DWORD
  Value: 0"
  tag "fix": "Configure the policy value for Computer Configuration ->
  Administrative Templates -> System -> Device Installation -> \"Prevent creation
  of a system restore point during device activity that would normally prompt
  creation of a restore point\" to \"Disabled\"."
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\DeviceInstall\\Settings") do
    it { should have_property "DisableSystemRestore" }
    its("DisableSystemRestore") { should cmp == 0 }
  end
end

