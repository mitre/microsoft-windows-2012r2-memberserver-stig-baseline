control "V-36707" do
  title "Windows SmartScreen must be configured to require approval from an
  administrator before running downloaded unknown software on Windows 2012/2012
  R2."
  desc  "Windows SmartScreen helps protect systems from programs downloaded
  from the internet that may be malicious. Requiring administrator approval
  before running unknown software will prevent potentially malicious programs
  from executing."
  impact 0.5
  tag "gtitle": "WINCC-000088"
  tag "gid": "V-36707"
  tag "rid": "SV-51747r3_rule"
  tag "stig_id": "WN12-CC-000088"
  tag "fix_id": "F-85265r2_fix"
  tag "cci": ["CCE-23531-7", "CCI-000381"]
  tag "nist": ["CM-7 a", "Rev_4"]
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\

  Value Name: EnableSmartScreen

  Type: REG_DWORD
  Value: 0x00000002 (2)"
  tag "fix": "Configure the policy value for Computer Configuration >>
  Administrative Templates >> Windows Components >> File Explorer >> \"Configure
  Windows SmartScreen\" to \"Enabled\" with \"Require approval from an
  administrator before running downloaded unknown software\" selected."
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System") do
    it { should have_property "EnableSmartScreen" }
    its("EnableSmartScreen") { should cmp == 2 }
  end
end

