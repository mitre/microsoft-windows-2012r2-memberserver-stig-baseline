control 'V-15700' do
  title "Remote access to the Plug and Play interface must be disabled for
  device installation."
  desc "Remote access to the Plug and Play interface could potentially allow
  connections by unauthorized devices.  This setting configures remote access to
  the Plug and Play interface and must be disabled."
  impact 0.5
  tag "gtitle": "Device Install \xE2\x80\x93 PnP Interface Remote Access"
  tag "gid": 'V-15700'
  tag "rid": 'SV-53094r1_rule'
  tag "stig_id": 'WN12-CC-000019'
  tag "fix_id": 'F-46020r1_fix'
  tag "cci": ['CCI-000381']
  tag "cce": ['CCE-24004-4']
  tag "nist": ['CM-7 a', 'Rev_4']
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path:
  \\Software\\Policies\\Microsoft\\Windows\\DeviceInstall\\Settings\\

  Value Name: AllowRemoteRPC

  Type: REG_DWORD
  Value: 0"
  tag "fix": "Configure the policy value for Computer Configuration ->
  Administrative Templates -> System -> Device Installation -> \"Allow remote
  access to the Plug and Play interface\" to \"Disabled\"."
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\DeviceInstall\\Settings') do
    it { should have_property 'AllowRemoteRPC' }
    its('AllowRemoteRPC') { should cmp == 0 }
  end
end
