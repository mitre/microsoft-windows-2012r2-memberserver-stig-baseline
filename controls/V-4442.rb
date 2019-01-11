control "V-4442" do
  title "The system must be configured to have password protection take effect
  within a limited time frame when the screen saver becomes active."
  desc  "Allowing more than several seconds makes the computer vulnerable to a
  potential attack from someone walking up to the console to attempt to log on to
  the system before the lock takes effect."
  impact 0.3
  tag "gtitle": "Screen Saver Grace Period"
  tag "gid": "V-4442"
  tag "rid": "SV-52930r1_rule"
  tag "stig_id": "WN12-SO-000046"
  tag "fix_id": "F-45856r2_fix"
  tag "cci": ['CCI-000366']
  tag "cce": ['CCE-24993-8']
  tag "nist": ['CM-6 b', 'Rev_4']
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
  Registry Path: \\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\

  Value Name: ScreenSaverGracePeriod

  Value Type: REG_SZ
  Value: 5 (or less)"
  tag "fix": "Configure the policy value for Computer Configuration -> Windows
  Settings -> Security Settings -> Local Policies -> Security Options -> \"MSS:
  (ScreenSaverGracePeriod) The time in seconds before the screen saver grace
  period expires (0 recommended)\" to \"5\" or less.

  (See \"Updating the Windows Security Options File\" in the STIG Overview
  document if MSS settings are not visible in the system's policy tools.)"
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon') do
    it { should have_property 'ScreenSaverGracePeriod' }
    its('ScreenSaverGracePeriod') { should cmp <= 5 }
  end
end

