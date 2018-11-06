control "V-3376" do
  title "The system must be configured to prevent the storage of passwords and
  credentials."
  desc  "This setting controls the storage of passwords and credentials for
  network authentication on the local system.  Such credentials must not be
  stored on the local machine, as that may lead to account compromise."
  impact 0.5
  tag "gtitle": "Storage of Passwords and Credentials"
  tag "gid": "V-3376"
  tag "rid": "SV-52889r1_rule"
  tag "stig_id": "WN12-SO-000053"
  tag "fix_id": "F-45815r1_fix"
  tag "cci": ["CCI-002038"]
  tag "cce": ["CCE-23358-5"]
  tag "nist": ["IA-11", "Rev_4"]
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\System\\CurrentControlSet\\Control\\Lsa\\

  Value Name: DisableDomainCreds

  Value Type: REG_DWORD
  Value: 1"
  tag "fix": "Configure the policy value for Computer Configuration -> Windows
  Settings -> Security Settings -> Local Policies -> Security Options ->
  \"Network access: Do not allow storage of passwords and credentials for network
  authentication\" to \"Enabled\"."
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa") do
    it { should have_property "DisableDomainCreds" }
    its("DisableDomainCreds") { should cmp == 1 }
  end
end

