control "V-15703" do
  title "Users must not be prompted to search Windows Update for device
  drivers."
  desc  "Some features may communicate with the vendor, sending system
  information or downloading data or components for the feature.  Turning off
  this capability will prevent potentially sensitive information from being sent
  outside the enterprise and uncontrolled updates to the system.
      This setting prevents users from being prompted to search Windows Update
  for device drivers.
  "
  impact 0.3
  tag "gtitle": "Driver Install – Device Driver Search Prompt"
  tag "gid": "V-15703"
  tag "rid": "SV-53115r1_rule"
  tag "stig_id": "WN12-CC-000026"
  tag "fix_id": "F-46041r1_fix"
  tag "cci": ["CCI-001812"]
  tag "cce": ["CCE-24804-7"]
  tag "nist": ["CM-11 (2)", "Rev_4"]
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\Software\\Policies\\Microsoft\\Windows\\DriverSearching\\

  Value Name: DontPromptForWindowsUpdate

  Type: REG_DWORD
  Value: 1"
  tag "fix": "Configure the policy value for Computer Configuration ->
  Administrative Templates -> System -> Driver Installation -> \"Turn off Windows
  Update device driver search prompt\" to \"Enabled\"."
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\DriverSearching") do
    it { should have_property "DontPromptForWindowsUpdate" }
    its("DontPromptForWindowsUpdate") { should cmp == 1 }
  end
end

