# frozen_string_literal: true

control 'V-15999' do
  title "Users must be prevented from redirecting Plug and Play devices to the
  Remote Desktop Session Host.  (Remote Desktop Services Role)."
  desc "Preventing the redirection of Plug and Play devices in Remote Desktop
  sessions helps reduce possible exposure of sensitive data."
  impact 0.5
  tag "gtitle": 'TS/RDS - PNP Device Redirection'
  tag "gid": 'V-15999'
  tag "rid": 'SV-52229r2_rule'
  tag "stig_id": 'WN12-CC-000135'
  tag "fix_id": 'F-45246r2_fix'
  tag "cci": ['CCI-002314']
  tag "cce": ['CCE-24708-0']
  tag "nist": ['AC-17 (1)', 'Rev_4']
  tag "documentable": false
  tag "ia_controls": 'ECSC-1'
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services\\

  Value Name: fDisablePNPRedir

  Type: REG_DWORD
  Value: 1"
  tag "fix": "Configure the policy value for Computer Configuration ->
  Administrative Templates -> Windows Components -> Remote Desktop Services ->
  Remote Desktop Session Host -> Device and Resource Redirection -> \"Do not
  allow supported Plug and Play device redirection\" to \"Enabled\"."

  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services') do
    it { should have_property 'fDisablePNPRedir' }
    its('fDisablePNPRedir') { should cmp == 1 }
  end
end
