control "V-15667" do
  title "Network Bridges must be prohibited in Windows."
  desc  "A Network Bridge can connect two or more network segments, allowing
  unauthorized access or exposure of sensitive data.  This setting prevents a
  Network Bridge from being installed and configured."
  impact 0.5
  tag "gtitle": "Prohibit Network Bridge"
  tag "gid": "V-15667"
  tag "rid": "SV-53014r2_rule"
  tag "stig_id": "WN12-CC-000004"
  tag "fix_id": "F-45941r1_fix"
  tag "cci": ["CCI-000381"]
  tag "cce": ["CCE-25587-7"]
  tag "nist": ["CM-7 a", "Rev_4"]
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\Software\\Policies\\Microsoft\\Windows\\Network Connections\\

  Value Name: NC_AllowNetBridge_NLA

  Type: REG_DWORD
  Value: 0"
  tag "fix": "Configure the policy value for Computer Configuration ->
  Administrative Templates -> Network -> Network Connections -> \"Prohibit
  installation and configuration of Network Bridge on your DNS domain network\"
  to \"Enabled\"."
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Network Connections") do
    it { should have_property "NC_AllowNetBridge_NLA" }
    its("NC_AllowNetBridge_NLA") { should cmp == 0 }
  end
end

