control "V-3666" do
  title "The system must be configured to meet the minimum session security
  requirement for NTLM SSP-based servers."
  desc  "Microsoft has implemented a variety of security support providers for
  use with RPC sessions.  All of the options must be enabled to ensure the
  maximum security level."
  impact 0.5
  tag "gtitle": "Session Security for NTLM SSP based Servers"
  tag "gid": "V-3666"
  tag "rid": "SV-52922r1_rule"
  tag "stig_id": "WN12-SO-000070"
  tag "fix_id": "F-45848r1_fix"
  tag "cci": ["CCE-25264-3", "CCI-000366"]
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\System\\CurrentControlSet\\Control\\Lsa\\MSV1_0\\

  Value Name: NTLMMinServerSec

  Value Type: REG_DWORD
  Value: 0x20080000 (537395200)"
  tag "fix": "Configure the policy value for Computer Configuration -> Windows
  Settings -> Security Settings -> Local Policies -> Security Options ->
  \"Network security: Minimum session security for NTLM SSP based (including
  secure RPC) servers\" to \"Require NTLMv2 session security\" and \"Require
  128-bit encryption\" (all options selected)."
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\MSV1_0") do
    it { should have_property "NTLMMinServerSec" }
    its("NTLMMinServerSec") { should cmp == 537395200}
  end
end

