control "V-21953" do
  title "PKU2U authentication using online identities must be prevented."
  desc  "PKU2U is a peer-to-peer authentication protocol.   This setting
  prevents online identities from authenticating to domain-joined systems.
  Authentication will be centrally managed with Windows user accounts."
  impact 0.5
  tag "gtitle": "PKU2U Online Identities Authentication"
  tag "gid": "V-21953"
  tag "rid": "SV-53178r1_rule"
  tag "stig_id": "WN12-SO-000063"
  tag "fix_id": "F-46104r1_fix"
  tag "cci": ["CCE-25299-9", "CCI-000366"]
  tag "nist": ["CCE-25299-9", "CCI-000366"]
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\System\\CurrentControlSet\\Control\\LSA\\pku2u\\

  Value Name: AllowOnlineID

  Type: REG_DWORD
  Value: 0"
  tag "fix": "Configure the policy value for Computer Configuration -> Windows
  Settings -> Security Settings -> Local Policies -> Security Options ->
  \"Network security: Allow PKU2U authentication requests to this computer to use
  online identities\" to \"Disabled\"."
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\pku2u") do
    it { should have_property "AllowOnlineID" }
    its("AllowOnlineID") { should cmp == 0 }
  end
end

