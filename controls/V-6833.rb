control "V-6833" do
  title "The Windows SMB server must be configured to always perform SMB packet
  signing."
  desc  "The server message block (SMB) protocol provides the basis for many
  network operations.  Digitally signed SMB packets aid in preventing
  man-in-the-middle attacks.  If this policy is enabled, the SMB server will only
  communicate with an SMB client that performs SMB packet signing."
  impact 0.5
  tag "gtitle": "SMB Server Packet Signing (Always)"
  tag "gid": "V-6833"
  tag "rid": "SV-52936r2_rule"
  tag "stig_id": "WN12-SO-000032"
  tag "fix_id": "F-45862r1_fix"
  tag "cci": ["CCI-002418", "CCI-002421"]
  tag "cce": ["CCE-23716-4"]
  tag "nist": ["SC-8", "Rev_4"]
  tag "nist": ["SC-8 (1)", "Rev_4"]
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\System\\CurrentControlSet\\Services\\LanManServer\\Parameters\\

  Value Name: RequireSecuritySignature

  Value Type: REG_DWORD
  Value: 1"
  tag "fix": "Configure the policy value for Computer Configuration -> Windows
  Settings -> Security Settings -> Local Policies -> Security Options ->
  \"Microsoft network server: Digitally sign communications (always)\" to
  \"Enabled\"."
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanmanServer\\Parameters") do
    it { should have_property "RequireSecuritySignature" }
    its("RequireSecuritySignature") { should cmp == 1 }
  end
end

