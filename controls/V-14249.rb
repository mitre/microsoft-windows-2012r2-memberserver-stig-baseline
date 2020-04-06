control 'V-14249' do
  title "Local drives must be prevented from sharing with Remote Desktop
  Session Hosts.  (Remote Desktop Services Role)."
  desc "Preventing users from sharing the local drives on their client
  computers to Remote Session Hosts that they access helps reduce possible
  exposure of sensitive data."
  impact 0.5
  tag "gtitle": 'TS/RDS - Drive Redirection'
  tag "gid": 'V-14249'
  tag "rid": 'SV-52959r1_rule'
  tag "stig_id": 'WN12-CC-000098'
  tag "fix_id": 'F-45885r1_fix'
  tag "cci": ['CCI-001090']
  tag "cce": ['CCE-24648-8']
  tag "nist": ['SC-4', 'Rev_4']
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services\\

  Value Name: fDisableCdm

  Type: REG_DWORD
  Value: 1"
  tag "fix": "Configure the policy value for Computer Configuration ->
  Administrative Templates -> Windows Components -> Remote Desktop Services ->
  Remote Desktop Session Host -> Device and Resource Redirection -> \"Do not
  allow drive redirection\" to \"Enabled\"."
  
  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services') do
    it { should have_property 'fDisableCdm' }
    its('fDisableCdm') { should cmp == 1 }
  end
end
