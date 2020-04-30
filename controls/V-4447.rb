# frozen_string_literal: true

control 'V-4447' do
  title "The Remote Desktop Session Host must require secure RPC
  communications."
  desc "Allowing unsecure RPC communication exposes the system to
  man-in-the-middle attacks and data disclosure attacks.  A man-in-the-middle
  attack occurs when an intruder captures packets between a client and server and
  modifies them before allowing the packets to be exchanged.  Usually the
  attacker will modify the information in the packets in an attempt to cause
  either the client or server to reveal sensitive information."
  impact 0.5
  tag "gtitle": 'TS/RDS -  Secure RPC Connection.'
  tag "gid": 'V-4447'
  tag "rid": 'SV-52932r2_rule'
  tag "stig_id": 'WN12-CC-000130'
  tag "fix_id": 'F-45858r2_fix'
  tag "cci": ['CCI-001453']
  tag "cce": ['CCE-24788-2']
  tag "nist": ['AC-17 (2)', 'Rev_4']
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services\\

  Value Name: fEncryptRPCTraffic

  Type: REG_DWORD
  Value: 1"
  tag "fix": "Configure the policy value for Computer Configuration ->
  Administrative Templates -> Windows Components -> Remote Desktop Services ->
  Remote Desktop Session Host -> Security -> \"Require secure RPC communication\"
  to \"Enabled\"."

  describe registry_key('HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services') do
    it { should have_property 'fEncryptRPCTraffic' }
    its('fEncryptRPCTraffic') { should cmp == 1 }
  end
end
