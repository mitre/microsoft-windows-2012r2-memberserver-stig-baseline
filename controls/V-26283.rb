control "V-26283" do
  title "Anonymous enumeration of SAM accounts must not be allowed."
  desc  "Anonymous enumeration of SAM accounts allows anonymous log on users
  (null session connections) to list all accounts names, thus providing a list of
  potential points to attack the system."
  impact 0.7
  tag "gtitle": "Restrict Anonymous SAM Enumeration"
  tag "gid": "V-26283"
  tag "rid": "SV-53122r1_rule"
  tag "stig_id": "WN12-SO-000051"
  tag "fix_id": "F-46048r1_fix"
  tag "cci": ["CCI-000366"]
  tag "cce": ["CCE-23082-1"]
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\System\\CurrentControlSet\\Control\\Lsa\\

  Value Name: RestrictAnonymousSAM

  Value Type: REG_DWORD
  Value: 1"
  tag "fix": "Configure the policy value for Computer Configuration -> Windows
  Settings -> Security Settings -> Local Policies -> Security Options ->
  \"Network access: Do not allow anonymous enumeration of SAM accounts\" to
  \"Enabled\"."
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa") do
    it { should have_property "RestrictAnonymousSAM" }
    its("RestrictAnonymousSAM") { should cmp == 1 }
  end
end

