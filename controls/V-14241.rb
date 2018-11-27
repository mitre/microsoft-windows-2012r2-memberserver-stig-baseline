control 'V-14241' do
  title "User Account Control must switch to the secure desktop when prompting
  for elevation."
  desc "User Account Control (UAC) is a security mechanism for limiting the
  elevation of privileges, including administrative accounts, unless authorized.
  This setting ensures that the elevation prompt is only used in secure desktop
  mode."
  impact 0.5
  tag "gtitle": 'UAC - Secure Desktop Mode'
  tag "gid": 'V-14241'
  tag "rid": 'SV-52952r1_rule'
  tag "stig_id": 'WN12-SO-000084'
  tag "fix_id": 'F-45878r2_fix'
  tag "cci": ['CCI-001084']
  tag "cce": ['CCE-23656-2']
  tag "nist": ['SC-3', 'Rev_4']
  tag "documentable": false
  tag "check": "UAC requirements are NA on Server Core installations.

  If the following registry value does not exist or is not configured as
  specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path:
  \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

  Value Name: PromptOnSecureDesktop

  Value Type: REG_DWORD
  Value: 1"
  tag "fix": "UAC requirements are NA on Server Core installations.

  Configure the policy value for Computer Configuration -> Windows Settings ->
  Security Settings -> Local Policies -> Security Options -> \"User Account
  Control: Switch to the secure desktop when prompting for elevation\" to
  \"Enabled\"."
  if registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Server\ServerLevels').has_property_value?('ServerCore', :dword, 1) && registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Server\ServerLevels').has_property_value?('Server-Gui-Mgmt', :dword, 1) && registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Server\ServerLevels').has_property_value?('Server-Gui-Shell', :dword, 1)
    impact 0.0
    describe 'This system is a Server Core Installation, control is NA' do
      skip 'This system is a Server Core Installation control is NA'
    end
  else
    describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System') do
      it { should have_property 'PromptOnSecureDesktop' }
      its('PromptOnSecureDesktop') { should cmp == 1 }
    end
  end
end
