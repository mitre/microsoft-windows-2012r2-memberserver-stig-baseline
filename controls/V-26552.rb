# frozen_string_literal: true

control 'V-26552' do
  title 'The system must be configured to audit System - IPsec Driver failures.'
  desc  "Maintaining an audit trail of system activity logs can help identify
  configuration errors, troubleshoot service disruptions, and analyze compromises
  that have occurred, as well as detect attacks.  Audit logs are necessary to
  provide a trail of evidence in case the system or network is compromised.
  Collecting this data is essential for analyzing the security of information
  assets and detecting signs of suspicious and unexpected behavior.

  IPsec Driver records events related to the IPsec Driver such as dropped
  packets.
  "
  impact 0.5
  tag "gtitle": 'Audit - IPSec Driver - Failure'
  tag "gid": 'V-26552'
  tag "rid": 'SV-52977r1_rule'
  tag "stig_id": 'WN12-AU-000104'
  tag "fix_id": 'F-45903r2_fix'
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

  Compare the AuditPol settings with the following.  If the system does not audit
  the following, this is a finding.

  System -> IPsec Driver - Failure"
  tag "fix": "Configure the policy value for Computer Configuration -> Windows
  Settings -> Security Settings -> Advanced Audit Policy Configuration -> System
  Audit Policies -> System -> \"Audit IPsec Driver\" with \"Failure\" selected."

  describe.one do
    describe audit_policy do
      its('IPsec Driver') { should eq 'Failure' }
    end
    describe audit_policy do
      its('IPsec Driver') { should eq 'Success and Failure' }
    end
  end
end
