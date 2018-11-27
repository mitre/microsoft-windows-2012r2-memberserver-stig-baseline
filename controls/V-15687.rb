control 'V-15687' do
  title "Users must not be presented with Privacy and Installation options on
  first use of Windows Media Player."
  desc  "Some features may communicate with the vendor, sending system
  information or downloading data or components for the feature.  Turning off
  this capability will prevent potentially sensitive information from being sent
  outside the enterprise and uncontrolled updates to the system.
      This setting prevents users from being presented with Privacy and
  Installation options on first use of Windows Media Player, which could enable
  some communication with the vendor.
  "
  impact 0.3
  tag "gtitle": "Media Player \xE2\x80\x93 First Use Dialog Boxes"
  tag "gid": 'V-15687'
  tag "rid": 'SV-53069r1_rule'
  tag "stig_id": 'WN12-CC-000121'
  tag "fix_id": 'F-45995r1_fix'
  tag "cci": ['CCI-000366']
  tag "cce": ['CCE-25014-2']
  tag "nist": ['CM-6 b', 'Rev_4']
  tag "documentable": false
  tag "check": "Windows Media Player is not installed by default.  If it is not
  installed, this is NA.

  If the following registry value does not exist or is not configured as
  specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\Software\\Policies\\Microsoft\\WindowsMediaPlayer\\

  Value Name: GroupPrivacyAcceptance

  Type: REG_DWORD
  Value: 1"
  tag "fix": "If Windows Media Player is installed, configure the policy value
  for Computer Configuration -> Administrative Templates -> Windows Components ->
  Windows Media Player -> \"Do Not Show First Use Dialog Boxes\" to \"Enabled\"."
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsMediaPlayer') do
    it { should have_property 'GroupPrivacyAcceptance' }
    its('GroupPrivacyAcceptance') { should cmp == 1 }
  end if registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsMediaPlayer').exists?

  if !registry_key('HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsMediaPlayer').exists?
    impact 0.0
    describe 'The system does not have Windows WindowsMediaPlayer installed' do
      skip "The system does not have Windows WindowsMediaPlayer installed, this requirement is Not
      Applicable."
    end
  end

end
