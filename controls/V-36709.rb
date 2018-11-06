control "V-36709" do
  title "Basic authentication for RSS feeds over HTTP must be turned off."
  desc  "Basic authentication uses plain text passwords that could be used to
  compromise a system."
  impact 0.5
  tag "gtitle": "WINCC-000106"
  tag "gid": "V-36709"
  tag "rid": "SV-51749r1_rule"
  tag "stig_id": "WN12-CC-000106"
  tag "fix_id": "F-44824r1_fix"
  tag "cci": ["CCI-000381"]
  tag "cce": ["CCE-23213-2"]
  tag "nist": ["CM-7 a", "Rev_4"]
  tag "documentable": false
  tag "ia_controls": "ECSC-1"
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\Software\\Policies\\Microsoft\\Internet Explorer\\Feeds\\

  Value Name: AllowBasicAuthInClear

  Type: REG_DWORD
  Value: 0"
  tag "fix": "Configure the policy value for Computer Configuration ->
  Administrative Templates -> Windows Components -> RSS Feeds -> \"Turn on Basic
  feed authentication over HTTP\" to \"Disabled\"."
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Internet Explorer\\Feeds") do
    it { should have_property "AllowBasicAuthInClear" }
    its("AllowBasicAuthInClear") { should cmp == 0 }
  end
end

