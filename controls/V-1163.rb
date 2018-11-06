control "V-1163" do
  title "Outgoing secure channel traffic must be encrypted when possible."
  desc  "Requests sent on the secure channel are authenticated, and sensitive
  information (such as passwords) is encrypted, but not all information is
  encrypted.  If this policy is enabled, outgoing secure channel traffic will be
  encrypted."
  impact 0.5
  tag "gtitle": "Encryption of Secure Channel Traffic"
  tag "gid": "V-1163"
  tag "rid": "SV-52871r3_rule"
  tag "stig_id": "WN12-SO-000013"
  tag "fix_id": "F-45797r2_fix"
  tag "cci": ["CCI-002421"]
  tag "cce": ["CCE-24414-5"]
  tag "nist": ["SC-8", "Rev_4"]
  tag "nist": ["SC-8 (2)", "Rev_4"]
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters\\

  Value Name: SealSecureChannel

  Value Type: REG_DWORD
  Value: 1

  If the value for \"Domain Member: Digitally encrypt or sign secure channel data
  (always)\" is set to \"Enabled\", this can be NA (see V-6831)."
  tag "fix": "Configure the policy value for Computer Configuration >> Windows
  Settings >> Security Settings >> Local Policies >> Security Options >> \"Domain
  member: Digitally encrypt secure channel data (when possible)\" to \"Enabled\"."
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters") do
    it { should have_property "SealSecureChannel" }
    its("SealSecureChannel") { should cmp == 1 }
  end
end

