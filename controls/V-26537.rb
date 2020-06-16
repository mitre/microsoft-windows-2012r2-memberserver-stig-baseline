# -*- encoding : utf-8 -*-
# frozen_string_literal: true

control 'V-26537' do
  title "The system must be configured to audit Account Management - User
  Account Management successes."
  desc "Maintaining an audit trail of system activity logs can help identify
  configuration errors, troubleshoot service disruptions, and analyze compromises
  that have occurred, as well as detect attacks.  Audit logs are necessary to
  provide a trail of evidence in case the system or network is compromised.
  Collecting this data is essential for analyzing the security of information
  assets and detecting signs of suspicious and unexpected behavior.

  User Account Management records events such as creating, changing,
  deleting, renaming, disabling, or enabling user accounts.
  "
  impact 0.5
  tag "gtitle": 'Audit - User Account Management - Success'
  tag "gid": 'V-26537'
  tag "rid": 'SV-53003r2_rule'
  tag "stig_id": 'WN12-AU-000019'
  tag "fix_id": 'F-45930r1_fix'
  tag "cci": %w[CCI-000018 CCI-000172 CCI-001403 CCI-001404
                CCI-001405 CCI-002130 CCI-002234]
  tag "nist": ['AC-2 (4)', 'AU-12 c', 'AC-6 (9)', 'Rev_4']
  tag "documentable": false
  tag "check": "Security Option \"Audit: Force audit policy subcategory
  settings (Windows Vista or later) to override audit policy category settings\"
  must be set to \"Enabled\" (V-14230) for the detailed auditing subcategories to
  be effective.

  Use the AuditPol tool to review the current Audit Policy configuration:
  -Open a Command Prompt with elevated privileges (\"Run as Administrator\").
  -Enter \"AuditPol /get /category:*\".

  Compare the AuditPol settings with the following.  If the system does not audit
  the following, this is a finding.

  Account Management -> User Account Management - Success"
  tag "fix": "Configure the policy value for Computer Configuration -> Windows
Settings -> Security Settings -> Advanced Audit Policy Configuration -> System
Audit Policies -> Account Management -> \"Audit User Account Management\" with
\"Success\" selected."

  describe.one do
    describe audit_policy do
      its('User Account Management') { should eq 'Success' }
    end
    describe audit_policy do
      its('User Account Management') { should eq 'Success and Failure' }
    end
  end
end
