control 'V-15686' do
  title "Nonadministrators must be prevented from applying vendor-signed
  updates."
  desc "Uncontrolled system updates can introduce issues to a system.  This
  setting will prevent users from applying vendor-signed updates (though they may
  be from a trusted source)."
  impact 0.3
  tag "gtitle": "Windows Installer \xE2\x80\x93 Vendor Signed Updates"
  tag "gid": 'V-15686'
  tag "rid": 'SV-53065r1_rule'
  tag "stig_id": 'WN12-CC-000118'
  tag "fix_id": 'F-45991r1_fix'
  tag "cci": ['CCI-001812']
  tag "cce": ['CCE-23601-8']
  tag "nist": ['CM-11 (2)', 'Rev_4']
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\Software\\Policies\\Microsoft\\Windows\\Installer\\

  Value Name: DisableLUAPatching

  Type: REG_DWORD
  Value: 1"
  tag "fix": "Configure the policy value for Computer Configuration ->
  Administrative Templates -> Windows Components -> Windows Installer ->
  \"Prohibit non-administrators from applying vendor signed updates\" to
  \"Enabled\"."
  
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Installer') do
    it { should have_property 'DisableLUAPatching' }
    its('DisableLUAPatching') { should cmp == 1 }
  end
end
