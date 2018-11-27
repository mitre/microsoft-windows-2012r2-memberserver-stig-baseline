control 'V-36708' do
  title 'The location feature must be turned off.'
  desc  "The location service on systems may allow sensitive data to be used by
  applications on the system.  This should be turned off unless explicitly
  allowed for approved systems/applications."
  impact 0.5
  tag "gtitle": 'WINCC-000095'
  tag "gid": 'V-36708'
  tag "rid": 'SV-51748r2_rule'
  tag "stig_id": 'WN12-CC-000095'
  tag "fix_id": 'F-44823r2_fix'
  tag "cci": ['CCI-000381']
  tag "cce": ['CCE-25343-5']
  tag "nist": ['CM-7 a', 'Rev_4']
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\Software\\Policies\\Microsoft\\Windows\\LocationAndSensors\\

  Value Name: DisableLocation

  Type: REG_DWORD
  Value: 1 (Enabled)

  If location services are approved for the system by the organization, this may
  be set to \"Disabled\" (0).  This must be documented with the ISSO."
  tag "fix": "Configure the policy value for Computer Configuration ->
  Administrative Templates -> Windows Components -> Location and Sensors ->
  \"Turn off location\" to \"Enabled\".

  If location services are approved by the organization for a device, this must
  be documented."
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\LocationAndSensors') do
    it { should have_property 'DisableLocation' }
    its('DisableLocation') { should cmp == 1 }
  end
end
