control "V-43238" do
  title "The display of slide shows on the lock screen must be disabled
  (Windows 2012 R2)."
  desc  "Slide shows that are displayed on the lock screen could display
  sensitive information to unauthorized personnel.  Turning off this feature will
  limit access to the information to a logged on user."
  if (os['release'].to_i < 6.3 )
    impact 0.0
  end
  else
    impact 0.5
  end
  tag "gtitle": "WINCC-000138"
  tag "gid": "V-43238"
  tag "rid": "SV-56343r2_rule"
  tag "stig_id": "WN12-CC-000138"
  tag "fix_id": "F-49190r1_fix"
  tag "cci": ["CCI-000381"]
  tag "nist": ["CM-7 a", "Rev_4"]
  tag "documentable": false
  tag "check": "This requirement is NA for the initial release of Windows 2012.
   It is applicable to Windows 2012 R2.

  Verify the registry value below.  If it does not exist or is not configured as
  specified, this is a finding.

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\Personalization\\
 
  Value Name: NoLockScreenSlideshow

  Value Type: REG_DWORD
  Value: 1"
  tag "fix": "This requirement is NA for the initial release of Windows 2012.
  It is applicable to Windows 2012 R2.

  Configure the policy value for Computer Configuration -> Administrative
  Templates -> Control Panel -> Personalization -> \"Prevent enabling lock screen
  slide show\" to \"Enabled\"."
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Personalization") do
    it { should have_property "NoLockScreenSlideshow" }
    its("NoLockScreenSlideshow") { should cmp == 1 }
  end
end

