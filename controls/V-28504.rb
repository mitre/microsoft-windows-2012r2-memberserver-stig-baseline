control "V-28504" do
  title "Windows must be prevented from sending an error report when a device
  driver requests additional software during installation."
  desc  "Some features may communicate with the vendor, sending system
  information or downloading data or components for the feature.  Turning off
  this capability will prevent potentially sensitive information from being sent
  outside the enterprise and uncontrolled updates to the system.
  This setting will prevent Windows from sending an error report to Microsoft
  when a device driver requests additional software during installation.
  "
  impact 0.3
  tag "gtitle": "Device Install Software Request Error Report"
  tag "gid": "V-28504"
  tag "rid": "SV-52962r1_rule"
  tag "stig_id": "WN12-CC-000023"
  tag "fix_id": "F-45888r1_fix"
  tag "cci": ["CCI-000381"]
  tag "cce": ["CCE-24685-0"]
  tag "nist": ["CM-7 a", "Rev_4"]
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path:
  \\Software\\Policies\\Microsoft\\Windows\\DeviceInstall\\Settings\\

  Value Name: DisableSendRequestAdditionalSoftwareToWER

  Type: REG_DWORD
  Value: 1"
  tag "fix": "Configure the policy value for Computer Configuration ->
  Administrative Templates -> System -> Device Installation -> \"Prevent Windows
  from sending an error report when a device driver requests additional software
  during installation\" to \"Enabled\"."
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\DeviceInstall\\Settings") do
    it { should have_property "DisableSendRequestAdditionalSoftwareToWER" }
    its("DisableSendRequestAdditionalSoftwareToWER") { should cmp == 1 }
  end
end

