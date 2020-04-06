control 'V-15702' do
  title "An Error Report must not be sent when a generic device driver is
  installed."
  desc "Some features may communicate with the vendor, sending system
  information or downloading data or components for the feature.  Turning off
  this capability will prevent potentially sensitive information from being sent
  outside the enterprise and uncontrolled updates to the system.
      This setting prevents an error report from being sent when a generic device
  driver is installed.
  "
  impact 0.3
  tag "gtitle": "Device Install \xE2\x80\x93 Generic Driver Error Report"
  tag "gid": 'V-15702'
  tag "rid": 'SV-53105r1_rule'
  tag "stig_id": 'WN12-CC-000020'
  tag "fix_id": 'F-46030r1_fix'
  tag "cci": ['CCI-000381']
  tag "cce": ['CCE-23275-1']
  tag "nist": ['CM-7 a', 'Rev_4']
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path:
  \\Software\\Policies\\Microsoft\\Windows\\DeviceInstall\\Settings\\

  Value Name: DisableSendGenericDriverNotFoundToWER

  Type: REG_DWORD
  Value: 1"
  tag "fix": "Configure the policy value for Computer Configuration ->
  Administrative Templates -> System -> Device Installation -> \"Do not send a
  Windows error report when a generic driver is installed on a device\" to
  \"Enabled\"."
  
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\DeviceInstall\\Settings') do
    it { should have_property 'DisableSendGenericDriverNotFoundToWER' }
    its('DisableSendGenericDriverNotFoundToWER') { should cmp == 1 }
  end
end
