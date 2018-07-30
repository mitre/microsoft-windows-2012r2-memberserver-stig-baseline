control "V-6831" do
  title "Outgoing secure channel traffic must be encrypted or signed."
  desc  "Requests sent on the secure channel are authenticated, and sensitive
  information (such as passwords) is encrypted, but not all information is
  encrypted.  If this policy is enabled, outgoing secure channel traffic will be
  encrypted and signed."
  impact 0.5
  tag "gtitle": "Encrypting and Signing of Secure Channel Traffic"
  tag "gid": "V-6831"
  tag "rid": "SV-52934r2_rule"
  tag "stig_id": "WN12-SO-000012"
  tag "fix_id": "F-45860r1_fix"
  tag "cci": ["CCE-24465-7", "CCI-002418", "CCI-002421"]
  tag "nist": ["CCE-24465-7", "CCI-002418", "CCI-002421"]
  tag "nist": ["SC-8", "Rev_4"]
  tag "nist": ["SC-8 (1)", "Rev_4"]
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\System\\CurrentControlSet\\Services\\Netlogon\\Parameters\\

  Value Name: RequireSignOrSeal

  Value Type: REG_DWORD
  Value: 1"
  tag "fix": "Configure the policy value for Computer Configuration -> Windows
  Settings -> Security Settings -> Local Policies -> Security Options -> \"Domain
  member: Digitally encrypt or sign secure channel data (always)\" to
  \"Enabled\"."
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters") do
    it { should have_property "RequireSignOrSeal" }
    its("RequireSignOrSeal") { should cmp == 1 }
  end
end

