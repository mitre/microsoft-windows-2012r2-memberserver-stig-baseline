control 'V-15997' do
  title "Users must be prevented from mapping local COM ports and redirecting
  data from the Remote Desktop Session Host to local COM ports.  (Remote Desktop
  Services Role)."
  desc "Preventing the redirection of Remote Desktop session data to a client
  computer's COM ports helps reduce possible exposure of sensitive data."
  impact 0.5
  tag "gtitle": "TS/RDS \xE2\x80\x93 COM Port Redirection"
  tag "gid": 'V-15997'
  tag "rid": 'SV-52224r2_rule'
  tag "stig_id": 'WN12-CC-000132'
  tag "fix_id": 'F-45242r2_fix'
  tag "cci": ['CCI-002314']
  tag "cce": ['CCE-24625-6']
  tag "nist": ['AC-17 (1)', 'Rev_4']
  tag "documentable": false
  tag "ia_controls": 'ECSC-1'
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services\\

  Value Name: fDisableCcm

  Type: REG_DWORD
  Value: 1"
  tag "fix": "Configure the policy value for Computer Configuration ->
  Administrative Templates -> Windows Components -> Remote Desktop Services ->
  Remote Desktop Session Host -> Device and Resource Redirection -> \"Do not
  allow COM port redirection\" to \"Enabled\"."
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services') do
    it { should have_property 'fDisableCcm' }
    its('fDisableCcm') { should cmp == 1 }
  end
end
