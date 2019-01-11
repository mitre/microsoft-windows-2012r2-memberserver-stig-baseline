control "V-21969" do
  title "Access to Windows Online Troubleshooting Service (WOTS) must be
  prevented."
  desc  "Some features may communicate with the vendor, sending system
  information or downloading data or components for the feature.  Turning off
  this capability will prevent potentially sensitive information from being sent
  outside the enterprise and uncontrolled updates to the system.
      This setting prevents users from searching troubleshooting content on
  Microsoft servers.  Only local content will be available.
  "
  impact 0.3
  tag "gtitle": "Windows Online Troubleshooting Service"
  tag "gid": "V-21969"
  tag "rid": "SV-53188r1_rule"
  tag "stig_id": "WN12-CC-000067"
  tag "fix_id": "F-46114r2_fix"
  tag "cci": ['CCI-000381']
  tag "cce": ['CCE-24776-7']
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
  Registry Path:
  \\Software\\Policies\\Microsoft\\Windows\\ScriptedDiagnosticsProvider\\Policy\\

  Value Name: EnableQueryRemoteServer

  Type: REG_DWORD
  Value: 0"
  tag "fix": "Configure the policy value for Computer Configuration ->
  Administrative Templates -> System -> Troubleshooting and Diagnostics ->
  Scripted Diagnostics -> \"Troubleshooting: Allow users to access online
  troubleshooting content on Microsoft servers from the Troubleshooting Control
  Panel (via the Windows Online Troubleshooting Service - WOTS)\" to
  \"Disabled\"."
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\ScriptedDiagnosticsProvider\\Policy') do
    it { should have_property 'EnableQueryRemoteServer' }
    its('EnableQueryRemoteServer') { should cmp == 0 }
  end
end

