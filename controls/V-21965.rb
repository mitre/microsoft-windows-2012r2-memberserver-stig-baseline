control "V-21965" do
  title "Device driver searches using Windows Update must be prevented."
  desc  "Some features may communicate with the vendor, sending system
  information or downloading data or components for the feature.  Turning off
  this capability will prevent potentially sensitive information from being sent
  outside the enterprise and uncontrolled updates to the system.
      This setting will prevent the system from searching Windows Update for
  device drivers.
  "
  impact 0.3
  tag "gtitle": "Prevent Windows Update for device driver search"
  tag "gid": "V-21965"
  tag "rid": "SV-53186r1_rule"
  tag "stig_id": "WN12-CC-000024"
  tag "fix_id": "F-46112r1_fix"
  tag "cci": ['CCI-001812']
  tag "cce": ['CCE-24777-5']
  tag "nist": ['CM-11 (2)', 'Rev_4']
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path:  \\Software\\Policies\\Microsoft\\Windows\\DriverSearching\\

  Value Name: SearchOrderConfig

  Type: REG_DWORD
  Value: 0"
  tag "fix": "Configure the policy value for Computer Configuration ->
  Administrative Templates -> System -> Device Installation -> \"Specify search
  order for device driver source locations\" to \"Enabled: Do not search Windows
  Update\"."
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\DriverSearching') do
    it { should have_property 'SearchOrderConfig' }
    its('SearchOrderConfig') { should cmp == 0 }
  end
end

