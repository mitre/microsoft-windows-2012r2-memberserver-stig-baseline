control "V-3449" do
  title "Remote Desktop Services must limit users to one remote session."
  desc  "Allowing multiple Remote Desktop Services sessions could consume
  resources.  There is also potential to make a secondary connection to a system
  with compromised credentials."
  impact 0.5
  tag "gtitle": "TS/RDS -  Session Limit"
  tag "gid": "V-3449"
  tag "rid": "SV-52216r2_rule"
  tag "stig_id": "WN12-CC-000131"
  tag "fix_id": "F-45235r2_fix"
  tag "cci": ["CCE-23328-8", "CCI-000054"]
  tag "nist": ["AC-10", "Rev_4"]
  tag "documentable": false
  tag "ia_controls": "ECLO-1, ECLO-2"
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services\\

  Value Name: fSingleSessionPerUser

  Type: REG_DWORD
  Value: 1"
  tag "fix": "Configure the policy value for Computer Configuration ->
  Administrative Templates -> Windows Components -> Remote Desktop Services ->
  Remote Desktop Session Host -> Connections -> \"Restrict Remote Desktop
  Services users to a single Remote Desktop Services Session\" to \"Enabled\"."
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services") do
    it { should have_property "fSingleSessionPerUser" }
    its("fSingleSessionPerUser") { should cmp == 1 }
  end
end

