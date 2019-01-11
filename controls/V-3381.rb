control "V-3381" do
  title "The system must be configured to the required LDAP client signing
  level."
  desc  "This setting controls the signing requirements for LDAP clients.  This
  setting must be set to Negotiate signing or Require signing, depending on the
  environment and type of LDAP server in use."
  impact 0.5
  tag "gtitle": "LDAP Client Signing"
  tag "gid": "V-3381"
  tag "rid": "SV-52894r1_rule"
  tag "stig_id": "WN12-SO-000068"
  tag "fix_id": "F-45820r1_fix"
  tag "cci": ['CCI-000366']
  tag "cce": ['CCE-25245-2']
  tag "nist": ['CM-6 b', 'Rev_4']
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\System\\CurrentControlSet\\Services\\LDAP\\

  Value Name: LDAPClientIntegrity

  Value Type: REG_DWORD
  Value: 1"
  tag "fix": "Configure the policy value for Computer Configuration -> Windows
  Settings -> Security Settings -> Local Policies -> Security Options ->
  \"Network security: LDAP client signing requirements\" to \"Negotiate signing\"
  at a minimum."
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LDAP') do
    it { should have_property 'LDAPClientIntegrity' }
    its('LDAPClientIntegrity') { should cmp == 1 }
  end
end

