# frozen_string_literal: true

control 'V-14229' do
  title 'Auditing of Backup and Restore Privileges must be turned off.'
  desc  "Maintaining an audit trail of system activity logs can help identify
  configuration errors, troubleshoot service disruptions, and analyze compromises
  that have occurred, as well as detect attacks.  Audit logs are necessary to
  provide a trail of evidence in case the system or network is compromised.
  Collecting this data is essential for analyzing the security of information
  assets and detecting signs of suspicious and unexpected behavior.
      This setting prevents the system from generating audit events for every
  file backed up or restored, which could fill the security log in Windows,
  making it difficult to identify actual issues.
  "
  impact 0.5
  tag "gtitle": 'Audit Backup and Restore Privileges'
  tag "gid": 'V-14229'
  tag "rid": 'SV-52943r1_rule'
  tag "stig_id": 'WN12-SO-000008'
  tag "fix_id": 'F-45869r1_fix'
  tag "cci": ['CCI-001095']
  tag "cce": ['CCE-24923-5']
  tag "nist": ['SC-5 (2)', 'Rev_4']
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\System\\CurrentControlSet\\Control\\Lsa\\

  Value Name: FullPrivilegeAuditing

  Value Type: REG_BINARY
  Value: 0"
  tag "fix": "Configure the policy value for Computer Configuration -> Windows
  Settings -> Security Settings -> Local Policies -> Security Options -> \"Audit:
  Audit the use of Backup and Restore privilege\" to \"Disabled\"."

  describe registry_key('HKEY_LOCAL_MACHINE\\System\\Currentcontrolset\\Control\\Lsa') do
    it { should have_property 'FullPrivilegeAuditing' }
    its('FullPrivilegeAuditing') { should cmp == 0 }
  end
end
