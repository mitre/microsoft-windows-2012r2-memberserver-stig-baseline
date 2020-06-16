# -*- encoding : utf-8 -*-
# frozen_string_literal: true

control 'V-26529' do
  title "The system must be configured to audit Account Logon - Credential
  Validation successes."
  desc "Maintaining an audit trail of system activity logs can help identify
  configuration errors, troubleshoot service disruptions, and analyze compromises
  that have occurred, as well as detect attacks.  Audit logs are necessary to
  provide a trail of evidence in case the system or network is compromised.
  Collecting this data is essential for analyzing the security of information
  assets and detecting signs of suspicious and unexpected behavior.

  Credential validation records events related to validation tests on
  credentials for a user account logon.
  "
  impact 0.5
  tag "gtitle": 'Audit - Credential Validation - Success'
  tag "gid": 'V-26529'
  tag "rid": 'SV-53013r2_rule'
  tag "stig_id": 'WN12-AU-000001'
  tag "fix_id": 'F-45940r1_fix'
  tag "cci": ['CCI-000172']
  tag "nist": ['AU-12 c', 'Rev_4']
  tag "documentable": false
  tag "check": "Security Option \"Audit: Force audit policy subcategory
  settings (Windows Vista or later) to override audit policy category settings\"
  must be set to \"Enabled\" (V-14230) for the detailed auditing subcategories to
  be effective.

  Use the AuditPol tool to review the current Audit Policy configuration:
  -Open a Command Prompt with elevated privileges (\"Run as Administrator\").
  -Enter \"AuditPol /get /category:*\".
Auditpol.exe /get /category:*
  Compare the AuditPol settings with the following.  If the system does not audit
  the following, this is a finding.

  Account Logon -> Credential Validation - Success"
  tag "fix": "Configure the policy value for Computer Configuration -> Windows
  Settings -> Security Settings -> Advanced Audit Policy Configuration -> System
  Audit Policies -> Account Logon -> \"Audit Credential Validation\" with
  \"Success\" selected."

  describe.one do
    describe audit_policy do
      its('Credential Validation') { should eq 'Success' }
    end
    describe audit_policy do
      its('Credential Validation') { should eq 'Success and Failure' }
    end
  end
end
