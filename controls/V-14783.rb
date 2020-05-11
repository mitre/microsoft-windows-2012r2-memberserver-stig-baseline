control "V-14783" do
  title "Separate, NSA-approved (Type 1) cryptography must be used to protect
the directory data-in-transit for directory service implementations at a
classified confidentiality level when replication data traverses a network
cleared to a lower level than the data."
  desc  "Commercial-grade encryption does not provide adequate protection when
the classification level of directory data in transit is higher than the level
of the network."
  impact 0.5
  tag 'severity': nil
  tag 'gtitle': 'Replication Encryption – Classification Factor'
  tag 'gid': 'V-14783'
  tag 'rid': 'SV-51185r3_rule'
  tag 'stig_id': 'WN12-AD-000011-DC'
  tag 'fix_id': 'F-44342r1_fix'
  tag 'cci': ["CCI-002450"]
  tag 'nist': ["SC-13", "Rev_4"]
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
  tag 'check': "With the assistance of the SA, NSO, or network reviewer as
required, review the site network diagram(s) or documentation to determine the
level of classification for the network(s) over which replication data is
transmitted.

Determine the classification level of the Windows domain controller.

If the classification level of the Windows domain controller is higher than the
level of the networks, review the site network diagram(s) and directory
implementation documentation to determine if NSA-approved encryption is used to
protect the replication network traffic.

If the classification level of the Windows domain controller is higher than the
level of the network traversed and NSA-approved encryption is not used, this is
a finding."
  tag 'fix': "Configure NSA-approved (Type 1) cryptography to protect the
directory data in transit for directory service implementations at a classified
confidentiality level that transfers replication data through a network cleared
to a lower level than the data."

 domain_role = command('wmic computersystem get domainrole | Findstr /v DomainRole').stdout.strip
  if domain_role == '4' || domain_role == '5'
    describe "Separate, NSA-approved (Type 1) cryptography must be used to protect the directory data in transit for directory service implementations at a
    classified confidentiality level when replication data traverses a network cleared to a lower level than the data." do
      skip "Separate, NSA-approved (Type 1) cryptography must be used to protect the directory data in transit for directory service implementations at a
    classified confidentiality level when replication data traverses a networkcleared to a lower level than the data is a manual check"
    end
  else
    impact 0.0
    desc 'This system is not a domain controller, therefore this control is not applicable as it only applies to domain controllers'
    describe 'This system is not a domain controller, therefore this control is not applicable as it only applies to domain controllers' do
      skip 'This system is not a domain controller, therefore this control is not applicable as it only applies to domain controllers'
    end
  end
end

