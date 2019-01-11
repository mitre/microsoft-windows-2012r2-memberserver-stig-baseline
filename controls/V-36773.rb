control "V-36773" do
  title "The machine inactivity limit must be set to 15 minutes, locking the
  system with the screensaver."
  desc  "Unattended systems are susceptible to unauthorized use and should be
  locked when unattended.  The screen saver should be set at a maximum of 15
  minutes and be password protected.  This protects critical and sensitive data
  from exposure to unauthorized personnel with physical access to the computer."
  impact 0.5
  tag "gtitle": "WINSO-000021"
  tag "gid": "V-36773"
  tag "rid": "SV-51596r2_rule"
  tag "stig_id": "WN12-SO-000021"
  tag "fix_id": "F-44717r2_fix"
  tag "cci": ['CCI-000057']
  tag "cce": ['CCE-23043-3']
  tag "nist": ['AC-11 a', 'Rev_4']
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
  \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

  Value Name: InactivityTimeoutSecs

  Value Type: REG_DWORD
  Value: 0x00000384 (900) (or less, excluding \"0\" which is effectively
  disabled)"
  tag "fix": "Configure the policy value for Computer Configuration -> Windows
  Settings -> Security Settings -> Local Policies -> Security Options ->
  \"Interactive logon: Machine inactivity limit\" to \"900\" seconds\" or less,
  excluding \"0\" which is effectively disabled."
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    it { should have_property 'InactivityTimeoutSecs' }
    its('InactivityTimeoutSecs') { should cmp <= 900 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
    it { should have_property 'InactivityTimeoutSecs' }
    its('InactivityTimeoutSecs') { should_not cmp 0 }
  end
end

