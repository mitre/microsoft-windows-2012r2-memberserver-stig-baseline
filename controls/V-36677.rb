control 'V-36677' do
  title "Optional component installation and component repair must be prevented
  from using Windows Update."
  desc "Uncontrolled system updates can introduce issues to a system.
  Obtaining update components from an outside source may also potentially provide
  sensitive information outside of the enterprise.  Optional component
  installation or repair must be obtained from an internal source."
  impact 0.3
  tag "gtitle": 'WINCC-000018'
  tag "gid": 'V-36677'
  tag "rid": 'SV-51606r1_rule'
  tag "stig_id": 'WN12-CC-000018'
  tag "fix_id": 'F-44727r1_fix'
  tag "cci": ['CCI-001812']
  tag "cce": ['CCE-23727-1']
  tag "nist": ['CM-11 (2)', 'Rev_4']
  tag "documentable": false
  tag "ia_controls": 'ECSC-1'
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path:
  \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Servicing\\

  Value Name: UseWindowsUpdate

  Type: REG_DWORD
  Value: 2"
  tag "fix": "Configure the policy value for Computer Configuration ->
  Administrative Templates -> System -> \"Specify settings for optional component
  installation and component repair\" to \"Enabled\" and with \"Never attempt to
  download payload from Windows Update\" selected."
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Servicing') do
    it { should have_property 'UseWindowsUpdate' }
    its('UseWindowsUpdate') { should cmp == 2 }
  end
end
