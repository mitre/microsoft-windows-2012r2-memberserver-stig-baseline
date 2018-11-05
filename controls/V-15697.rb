control "V-15697" do
  title "The Responder network protocol driver must be disabled."
  desc  "The Responder network protocol driver allows a computer to be
  discovered and located on a network.  Disabling this helps protect the system
  from potentially being discovered and connected to by unauthorized devices."
  impact 0.5
  tag "gtitle": "Network – Responder Driver"
  tag "gid": "V-15697"
  tag "rid": "SV-53081r1_rule"
  tag "stig_id": "WN12-CC-000002"
  tag "fix_id": "F-46007r1_fix"
  tag "cci": ["CCE-23931-9", "CCI-000381"]
  tag "nist": ["CM-7 a", "Rev_4"]
  tag "documentable": false
  tag "check": "If the following registry values do not exist or are not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\Software\\Policies\\Microsoft\\Windows\\LLTD\\

  Value Name: AllowRspndrOndomain
  Value Name: AllowRspndrOnPublicNet
  Value Name: EnableRspndr
  Value Name: ProhibitRspndrOnPrivateNet

  Type: REG_DWORD
  Value: 0"
  tag "fix": "Configure the policy value for Computer Configuration ->
  Administrative Templates -> Network -> Link-Layer Topology Discovery -> \"Turn
  on Responder (RSPNDR) driver\" to \"Disabled\"."
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\LLTD") do
    it { should have_property "AllowRspndrOnDomain" }
    its("AllowRspndrOnDomain") { should cmp == 0 }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\LLTD") do
    it { should have_property "AllowRspndrOnPublicNet" }
    its("AllowRspndrOnPublicNet") { should cmp == 0 }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\LLTD") do
    it { should have_property "EnableRspndr" }
    its("EnableRspndr") { should cmp == 0 }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\LLTD") do
    it { should have_property "ProhibitRspndrOnPrivateNet" }
    its("ProhibitRspndrOnPrivateNet") { should cmp == 0 }
  end
end

