control "V-15684" do
  title "Users must be notified if a web-based program attempts to install
  software."
  desc  "Users must be aware of attempted program installations.  This setting
  ensures users are notified if a web-based program attempts to install software."
  impact 0.5
  tag "gtitle": "Windows Installer – IE Security Prompt"
  tag "gid": "V-15684"
  tag "rid": "SV-53056r2_rule"
  tag "stig_id": "WN12-CC-000117"
  tag "fix_id": "F-45982r1_fix"
  tag "cci": ["CCE-23886-5", "CCI-000366"]
  tag "nist": ["CCE-23886-5", "CCI-000366"]
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\Software\\Policies\\Microsoft\\Windows\\Installer\\

  Value Name: SafeForScripting

  Type: REG_DWORD
  Value: 0"
  tag "fix": "Configure the policy value for Computer Configuration ->
  Administrative Templates -> Windows Components -> Windows Installer ->
  \"Prevent Internet Explorer security prompt for Windows Installer scripts\" to
  \"Disabled\"."
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Installer") do
    it { should have_property "SafeForScripting" }
    its("SafeForScripting") { should cmp == 0 }
  end
end

