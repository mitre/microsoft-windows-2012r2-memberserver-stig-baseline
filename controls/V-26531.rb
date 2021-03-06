control "V-26531" do
  title "Windows Server 2012/2012 R2 domain controllers must be configured to
audit Account Management - Computer Account Management successes."
  desc  "Maintaining an audit trail of system activity logs can help identify
configuration errors, troubleshoot service disruptions, and analyze compromises
that have occurred, as well as detect attacks.  Audit logs are necessary to
provide a trail of evidence in case the system or network is compromised.
Collecting this data is essential for analyzing the security of information
assets and detecting signs of suspicious and unexpected behavior.

    Computer Account Management records events such as creating, changing,
deleting, renaming, disabling, or enabling computer accounts."
  impact 0.5
  tag 'severity': nil
  tag 'gtitle': 'Audit - Computer Account Management - Success'
  tag 'gid': 'V-26531'
  tag 'rid': 'SV-52234r4_rule'
  tag 'stig_id': 'WN12-AU-000011-DC'
  tag 'fix_id': 'F-45249r2_fix'
  tag 'cci': ["CCI-000172", "CCI-002234"]
  tag 'nist': ["AU-12 c", "AC-6 (9)", "Rev_4"]
  tag 'false_negatives': nil
  tag 'false_positives': nil
  tag 'documentable': false
  tag 'mitigations': nil
  tag 'severity_override_guidance': false
  tag 'potential_impacts': nil
  tag 'third_party_tools': nil
  tag 'mitigation_controls': nil
  tag 'responsibility': nil
  tag 'ia_controls': nil
  tag 'check': "Security Option \"Audit: Force audit policy subcategory settings
(Windows Vista or later) to override audit policy category settings\" must be
set to \"Enabled\" (V-14230) for the detailed auditing subcategories to be
effective.

Use the AuditPol tool to review the current Audit Policy configuration:
-Open a Command Prompt with elevated privileges (\"Run as Administrator\").
-Enter \"AuditPol /get /category:*\".

Compare the AuditPol settings with the following.  If the system does not audit
the following, this is a finding.

Account Management >> Computer Account Management - Success"
  tag 'fix': "Configure the policy value for Computer Configuration >> Windows
Settings >> Security Settings >> Advanced Audit Policy Configuration >> System
Audit Policies >> Account Management >> \"Audit Computer Account Management\"
with \"Success\" selected."

domain_role = command('wmic computersystem get domainrole | Findstr /v DomainRole').stdout.strip
  if domain_role == '4' || domain_role == '5'
     describe.one do
      describe audit_policy do
       its('Computer Account Management') { should eq 'Success' }
      end
      describe audit_policy do
       its('Computer Account Management') { should eq 'Success and Failure' }
      end
     end
  else
    impact 0.0
    desc 'This system is not a domain controller, therefore this control is not applicable as it only applies to domain controllers'
     describe 'This system is not a domain controller, therefore this control is not applicable as it only applies to domain controllers' do
      skip 'This system is not a domain controller, therefore this control is not applicable as it only applies to domain controllers'
     end
  end
end