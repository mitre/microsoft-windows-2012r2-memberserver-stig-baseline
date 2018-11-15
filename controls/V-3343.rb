control "V-3343" do
  title "Solicited Remote Assistance must not be allowed."
  desc  "Remote assistance allows another user to view or take control of the
  local session of a user.  Solicited assistance is help that is specifically
  requested by the local user.  This may allow unauthorized parties access to the
  resources on the computer."
  impact 0.7
  tag "gtitle": "Remote Assistance - Solicit Remote Assistance"
  tag "gid": "V-3343"
  tag "rid": "SV-52885r1_rule"
  tag "stig_id": "WN12-CC-000059"
  tag "fix_id": "F-45811r1_fix"
  tag "cci": ["CCI-001090"]
  tag "cce": ["CCE-25590-1"]
  tag "nist": ["SC-4", "Rev_4"]
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services\\

  Value Name: fAllowToGetHelp

  Type: REG_DWORD
  Value: 0"
  tag "fix": "Configure the policy value for Computer Configuration ->
  Administrative Templates -> System -> Remote Assistance -> \"Configure
  Solicited Remote Assistance\" to \"Disabled\"."
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services") do
    it { should have_property "fAllowToGetHelp" }
    its("fAllowToGetHelp") { should cmp == 0 }
  end
end

