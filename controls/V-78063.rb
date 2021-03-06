# -*- encoding : utf-8 -*-
# frozen_string_literal: true

control 'V-78063' do
  title "Windows Server 2012/2012 R2 must be configured to audit System - Other
  System Events failures."
  desc "Maintaining an audit trail of system activity logs can help identify
  configuration errors, troubleshoot service disruptions, and analyze compromises
  that have occurred, as well as detect attacks. Audit logs are necessary to
  provide a trail of evidence in case the system or network is compromised.
  Collecting this data is essential for analyzing the security of information
  assets and detecting signs of suspicious and unexpected behavior.

  Audit Other System Events records information related to cryptographic key
  operations and the Windows Firewall service.
  "
  impact 0.5
  tag "gtitle": 'WINAU-000908'
  tag "gid": 'V-78063'
  tag "rid": 'SV-92781r1_rule'
  tag "stig_id": 'WN12-AU-000106'
  tag "fix_id": 'F-84799r1_fix'
  tag "cci": %w[CCI-000172 CCI-002234]
  tag "nist": ['AU-12 c', 'AC-6 (9)', 'Rev_4']
  tag "documentable": false
  tag "check": "Security Option \"Audit: Force audit policy subcategory
  settings (Windows Vista or later) to override audit policy category settings\"
  must be set to \"Enabled\" (V-14230) for the detailed auditing subcategories to
  be effective.

  Use the AuditPol tool to review the current Audit Policy configuration:

  Open an elevated \"Command Prompt\" (run as administrator).

  Enter \"AuditPol /get /category:*\".

  Compare the AuditPol settings with the following.

  If the system does not audit the following, this is a finding.

  System >> Other System Events - Failure"
  tag "fix": "Configure the policy value for Computer Configuration >> Windows
  Settings >> Advanced Audit Policy Configuration >> System Audit Policies >>
  System >> \"Audit Other System Events\" with \"Failure\" selected."

  describe.one do
    describe audit_policy do
      its('Other System Events') { should eq 'Failure' }
    end
    describe audit_policy do
      its('Other System Events') { should eq 'Success and Failure' }
    end
  end
end
