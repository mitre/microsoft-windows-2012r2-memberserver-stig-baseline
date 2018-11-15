control "V-14253" do
  title "Unauthenticated RPC clients must be restricted from connecting to the
  RPC server."
  desc  "Configuring RPC to restrict unauthenticated RPC clients from
  connecting to the RPC server will prevent anonymous connections."
  impact 0.5
  tag "gtitle": "RPC - Unauthenticated RPC Clients"
  tag "gid": "V-14253"
  tag "rid": "SV-52988r2_rule"
  tag "stig_id": "WN12-CC-000064-MS"
  tag "fix_id": "F-45914r2_fix"
  tag "cci": ["CCI-001967"]
  tag "cce": ["CCE-24152-1"]
  tag "nist": ["IA-3 (1)", "Rev_4"]
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive:  HKEY_LOCAL_MACHINE
  Registry Path:  \\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Rpc\\

  Value Name:  RestrictRemoteClients

  Type:  REG_DWORD
  Value:  1"
  tag "fix": "Configure the policy value for Computer Configuration ->
  Administrative Templates -> System -> Remote Procedure Call -> \"Restrict
  Unauthenticated RPC clients\" to \"Enabled\" and \"Authenticated\"."
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Rpc") do
    it { should have_property "RestrictRemoteClients" }
    its("RestrictRemoteClients") { should cmp == 1 }
  end
end

