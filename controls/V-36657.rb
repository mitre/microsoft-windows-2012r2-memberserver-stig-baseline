control "V-36657" do
  title "The screen saver must be password protected."
  desc  "Unattended systems are susceptible to unauthorized use and must be
  locked when unattended.  Enabling a password-protected screen saver to engage
  after a specified period of time helps protects critical and sensitive data
  from exposure to unauthorized personnel with physical access to the computer."
  impact 0.5
  tag "gtitle": "WINUC-000003"
  tag "gid": "V-36657"
  tag "rid": "SV-51760r1_rule"
  tag "stig_id": "WN12-UC-000003"
  tag "fix_id": "F-44835r1_fix"
  tag "cci": ['CCI-000056']
  tag "cce": ['CCE-24680-1']
  tag "nist": ['AC-11 b', 'Rev_4']
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": "PESL-1"
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_CURRENT_USER
  Registry Path: \\Software\\Policies\\Microsoft\\Windows\\Control
  Panel\\Desktop\\

  Value Name: ScreenSaverIsSecure

  Type: REG_SZ
  Value: 1"
  tag "fix": "Configure the policy value for User Configuration ->
  Administrative Templates -> Control Panel -> Personalization -> \"Password
  protect the screen saver\" to \"Enabled\"."
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Control
  Panel\\Desktop") do
    it { should have_property 'ScreenSaverIsSecure' }
    its('ScreenSaverIsSecure') { should cmp == 1 }
  end
end

