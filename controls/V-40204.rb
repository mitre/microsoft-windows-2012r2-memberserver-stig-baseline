control 'V-40204' do
  title "Only the default client printer must be redirected to the Remote
  Desktop Session Host.  (Remote Desktop Services Role)."
  desc "Allowing the redirection of only the default client printer to a
  Remote Desktop session helps reduce possible exposure of sensitive data."
  impact 0.5
  tag "gtitle": 'WNCC-000136'
  tag "gid": 'V-40204'
  tag "rid": 'SV-52163r2_rule'
  tag "stig_id": 'WN12-CC-000136'
  tag "fix_id": 'F-45188r2_fix'
  tag "cci": ['CCI-000366']
  tag "cce": ['CCE-24504-3']
  tag "nist": ['CM-6 b', 'Rev_4']
  tag "documentable": false
  tag "ia_controls": 'ECSC-1'
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services\\

  Value Name: RedirectOnlyDefaultClientPrinter

  Type: REG_DWORD
  Value: 1"
  tag "fix": "Configure the policy value for Computer Configuration ->
  Administrative Templates -> Windows Components -> Remote Desktop Services ->
  Remote Desktop Session Host -> Printer Redirection -> \"Redirect only the
  default client printer\" to \"Enabled\"."
  
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services') do
    it { should have_property 'RedirectOnlyDefaultClientPrinter' }
    its('RedirectOnlyDefaultClientPrinter') { should cmp == 1 }
  end
end
