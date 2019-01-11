control "V-36736" do
  title "The system must query the certification authority to determine whether
  a public key certificate has been revoked before accepting the certificate for
  authentication purposes."
  desc  "Failure to verify a certificate's revocation status can result in the
  system accepting a revoked, and therefore unauthorized, certificate.  This
  could result in the installation of unauthorized software or a connection for
  rogue networks, depending on the use for which the certificate is intended.
  Querying for certificate revocation mitigates the risk that the system will
  accept an unauthorized certificate."
  impact 0.5
  tag "gtitle": "WINGE-000030"
  tag "gid": "V-36736"
  tag "rid": "SV-51584r1_rule"
  tag "stig_id": "WN12-GE-000025"
  tag "fix_id": "F-44713r1_fix"
  tag "cci": ["CCI-000366"]
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
  tag "check": "Verify the system has software installed and running that
  provides certificate validation and revocation checking.  If it does not, this
  is a finding."
  tag "fix": "Install software that  provides certificate validation and
  revocation checking."
  describe 'A manual review is required to ensure the system must querys the certification authority to determine whether
  a public key certificate has been revoked before accepting the certificate for
  authentication purposes' do
    skip "A manual review is required to ensure the system must querys the certification authority to determine whether
  a public key certificate has been revoked before accepting the certificate for
  authentication purposes"
  end
end

