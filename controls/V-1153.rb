control "V-1153" do
  title "The LanMan authentication level must be set to send NTLMv2 response
  only, and to refuse LM and NTLM."
  desc  "The Kerberos v5 authentication protocol is the default for
  authentication of users who are logging on to domain accounts.  NTLM, which is
  less secure, is retained in later Windows versions  for compatibility with
  clients and servers that are running earlier versions of Windows or
  applications that still use it.  It is also used to authenticate logons to
  stand-alone computers that are running later versions."
  impact 0.7
  tag "gtitle": "LanMan Authentication Level"
  tag "gid": "V-1153"
  tag "rid": "SV-52865r1_rule"
  tag "stig_id": "WN12-SO-000067"
  tag "fix_id": "F-45791r1_fix"
  tag "cci": ["CCE-24650-4", "CCI-000366"]
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\System\\CurrentControlSet\\Control\\Lsa\\

  Value Name: LmCompatibilityLevel

  Value Type: REG_DWORD
  Value: 5"
  tag "fix": "Configure the policy value for Computer Configuration -> Windows
  Settings -> Security Settings -> Local Policies -> Security Options ->
  \"Network security: LAN Manager authentication level\" to \"Send NTLMv2
  response only. Refuse LM & NTLM\"."
  describe registry_key("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa") do
    it { should have_property "LmCompatibilityLevel" }
    its("LmCompatibilityLevel") { should cmp == 5 }
  end
end

