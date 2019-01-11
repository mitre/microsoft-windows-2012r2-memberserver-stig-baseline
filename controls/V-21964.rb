control "V-21964" do
  title "Device metadata retrieval from the Internet must be prevented."
  desc  "Some features may communicate with the vendor, sending system
  information or downloading data or components for the feature.  Turning off
  this capability will prevent potentially sensitive information from being sent
  outside the enterprise and uncontrolled updates to the system.
      This setting will prevent Windows from retrieving device metadata from the
  Internet.
  "
  impact 0.3
  tag "gtitle": "Prevent device metadata retrieval from Internet"
  tag "gid": "V-21964"
  tag "rid": "SV-53185r2_rule"
  tag "stig_id": "WN12-CC-000022"
  tag "fix_id": "F-46111r3_fix"
  tag "cci": ['CCI-000381']
  tag "cce": ['CCE-24165-3']
  tag "nist": ['CM-7 a', 'Rev_4']
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

  Registry Hive:  HKEY_LOCAL_MACHINE
  Registry Path:  \\SOFTWARE\\Policies\\Microsoft\\Windows\\Device Metadata\\

  Value Name:  PreventDeviceMetadataFromNetwork

  Value Type:  REG_DWORD
  Value:  1"
  tag "fix": "Configure the policy value for Computer Configuration >>
  Administrative Templates >> System >> Device Installation >> \"Prevent device
  metadata retrieval from the Internet\" to \"Enabled\"."
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Device Metadata') do
    it { should have_property 'PreventDeviceMetadataFromNetwork' }
    its('PreventDeviceMetadataFromNetwork') { should cmp == 1 }
  end
end

