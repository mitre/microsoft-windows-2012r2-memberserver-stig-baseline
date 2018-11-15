control "V-21970" do
  title "Responsiveness events must be prevented from being aggregated and sent
  to Microsoft."
  desc  "Some features may communicate with the vendor, sending system
  information or downloading data or components for the feature.  Turning off
  this capability will prevent potentially sensitive information from being sent
  outside the enterprise and uncontrolled updates to the system.
      This setting prevents responsiveness events from being aggregated and sent
  to Microsoft.
  "
  impact 0.3
  tag "gtitle": "Disable PerfTrack"
  tag "gid": "V-21970"
  tag "rid": "SV-53128r1_rule"
  tag "stig_id": "WN12-CC-000068"
  tag "fix_id": "F-46054r1_fix"
  tag "cci": ["CCI-000381"]
  tag "cce": ["CCE-25080-3"]
  tag "nist": ["CM-7 a", "Rev_4"]
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path:
  \\Software\\Policies\\Microsoft\\Windows\\WDI\\{9c5a40da-b965-4fc3-8781-88dd50a6299d}\\

  Value Name: ScenarioExecutionEnabled

  Type: REG_DWORD
  Value: 0"
  tag "fix": "Configure the policy value for Computer Configuration ->
  Administrative Templates -> System -> Troubleshooting and Diagnostics ->
  Windows Performance PerfTrack -> \"Enable/Disable PerfTrack\" to \"Disabled\"."
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WDI\\{9c5a40da-b965-4fc3-8781-88dd50a6299d}") do
    it { should have_property "ScenarioExecutionEnabled" }
    its("ScenarioExecutionEnabled") { should cmp == 0 }
  end
end

