control "V-16020" do
  title "The Windows Customer Experience Improvement Program must be disabled."
  desc  "Some features may communicate with the vendor, sending system
  information or downloading data or components for the feature.  Turning off
  this capability will prevent potentially sensitive information from being sent
  outside the enterprise and uncontrolled updates to the system.
      This setting ensures the Windows Customer Experience Improvement Program is
  disabled so information is not passed to the vendor.
  "
  impact 0.5
  tag "gtitle": "Windows Customer Experience Improvement Program "
  tag "gid": "V-16020"
  tag "rid": "SV-53143r1_rule"
  tag "stig_id": "WN12-CC-000045"
  tag "fix_id": "F-46069r1_fix"
  tag "cci": ['CCI-000381']
  tag "cce": ['CCE-24082-0']
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

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\Software\\Policies\\Microsoft\\SQMClient\\Windows\\

  Value Name: CEIPEnable

  Type: REG_DWORD
  Value: 0"
  tag "fix": "Configure the policy value for Computer Configuration ->
  Administrative Templates -> System -> Internet Communication Management ->
  Internet Communication Settings -> \"Turn off Windows Customer Experience
  Improvement Program\" to \"Enabled\"."
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\SQMClient\\Windows') do
    it { should have_property 'CEIPEnable' }
    its('CEIPEnable') { should cmp == 0 }
  end
end

