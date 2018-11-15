control "V-1151" do
  title "The print driver installation privilege must be restricted to
  administrators."
  desc  "Allowing users to install drivers can introduce malware or cause the
  instability of a system.  Print driver installation should be restricted to
  administrators."
  impact 0.3
  tag "gtitle": "Secure Print Driver Installation"
  tag "gid": "V-1151"
  tag "rid": "SV-52214r2_rule"
  tag "stig_id": "WN12-SO-000089"
  tag "fix_id": "F-45233r2_fix"
  tag "cci": ["CCI-001812"]
  tag "cce": ["CCE-25176-9"]
  tag "nist": ["CM-11 (2)" "Rev_4"]
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\System\\CurrentControlSet\\Control\\Print\\Providers\\LanMan
  Print Services\\Servers\\

  Value Name: AddPrinterDrivers

  Value Type: REG_DWORD
  Value: 1"
  tag "fix": "Configure the policy value for Computer Configuration -> Windows
  Settings -> Security Settings -> Local Policies -> Security Options ->
  \"Devices: Prevent users from installing printer drivers\" to \"Enabled\"."
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Print\\Providers\\LanMan Print Services\\Servers") do
    it { should have_property "AddPrinterDrivers" }
    its("AddPrinterDrivers") { should cmp == 1 }
  end
end

