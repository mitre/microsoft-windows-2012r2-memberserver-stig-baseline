control "V-40237" do
  title "The US DoD CCEB Interoperability Root CA cross-certificates must be
  installed into the Untrusted Certificates Store on unclassified systems."
  desc  "To ensure users do not experience denial of service when performing
  certificate-based authentication to DoD websites due to the system chaining to
  a root other than DoD Root CAs, the US DoD CCEB Interoperability Root CA
  cross-certificates must be installed in the Untrusted Certificate Store. This
  requirement only applies to unclassified systems."
  impact 0.5
  tag "gtitle": "WINPK-000004"
  tag "gid": "V-40237"
  tag "rid": "SV-52196r5_rule"
  tag "stig_id": "WN12-PK-000004"
  tag "fix_id": "F-87319r1_fix"
  tag "cci": ["CCI-000185", "CCI-002470"]
  tag "nist": ['IA-5 (2) (a)', 'Rev_4']
  tag "nist": ['SC-23 (5)', 'Rev_4']
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
  tag "check": "Verify the US DoD CCEB Interoperability Root CA
  cross-certificate is installed on unclassified systems as an Untrusted
  Certificate.

  Run \"PowerShell\" as an administrator.

  Execute the following command:

  Get-ChildItem -Path Cert:Localmachine\\disallowed | Where Issuer -Like \"*CCEB
  Interoperability*\" | FL Subject, Issuer, Thumbprint, NotAfter

  If the following certificate \"Subject\", \"Issuer\", and \"Thumbprint\"
  information is not displayed, this is finding.

  If an expired certificate (\"NotAfter\" date) is not listed in the results,
  this is not a finding.

  Subject: CN=DoD Root CA 2, OU=PKI, OU=DoD, O=U.S. Government, C=US
  Issuer: CN=US DoD CCEB Interoperability Root CA 1, OU=PKI, OU=DoD, O=U.S.
  Government, C=US
  Thumbprint: DA36FAF56B2F6FBA1604F5BE46D864C9FA013BA3
  NotAfter: 3/9/2019

  Subject: CN=DoD Root CA 3, OU=PKI, OU=DoD, O=U.S. Government, C=US
  Issuer: CN=US DoD CCEB Interoperability Root CA 2, OU=PKI, OU=DoD, O=U.S.
  Government, C=US
  Thumbprint: 929BF3196896994C0A201DF4A5B71F603FEFBF2E
  NotAfter: 9/27/2019

  Alternately use the Certificates MMC snap-in:

  Run \"MMC\".

  Select \"File\", \"Add/Remove Snap-in\".

  Select \"Certificates\", click \"Add\".

  Select \"Computer account\", click \"Next\".

  Select \"Local computer: (the computer this console is running on)\", click
  \"Finish\".

  Click \"OK\".

  Expand \"Certificates\" and navigate to \"Untrusted Certificates >>
  Certificates\".

  For each certificate with \"US DoD CCEB Interoperability Root CA …\" under
  \"Issued By\":

  Right-click on the certificate and select \"Open\".

  Select the \"Details\" Tab.

  Scroll to the bottom and select \"Thumbprint\".

  If the certificate below is not listed or the value for the \"Thumbprint\"
  field is not as noted, this is a finding.

  If an expired certificate (\"Valid to\" date) is not listed in the results,
  this is not a finding.

  Issued To: DoD Root CA 2
  Issued By: US DoD CCEB Interoperability Root CA 1
  Thumbprint: DA36FAF56B2F6FBA1604F5BE46D864C9FA013BA3
  Valid to: Saturday, March 9, 2019

  Issued To: DoD Root CA 3
  Issuer by: US DoD CCEB Interoperability Root CA 2
  Thumbprint: 929BF3196896994C0A201DF4A5B71F603FEFBF2E
  Valid: Friday, September 27, 2019"
  tag "fix": "Install the US DoD CCEB Interoperability Root CA
  cross-certificate on unclassified systems.

  Issued To - Issued By - Thumbprint
  DoD Root CA 2 - US DoD CCEB Interoperability Root CA 1 -
  DA36FAF56B2F6FBA1604F5BE46D864C9FA013BA3

  DoD Root CA 3 - US DoD CCEB Interoperability Root CA 2 -
  929BF3196896994C0A201DF4A5B71F603FEFBF2E

  Administrators should run the Federal Bridge Certification Authority (FBCA)
  Cross-Certificate Removal Tool once as an administrator and once as the current
  user.

  The FBCA Cross-Certificate Remover tool and user guide is available on IASE at
  http://iase.disa.mil/pki-pke/Pages/tools.aspx."
  describe 'The installed DoD CCEB Interoperability Root CA cross-certificate' do
    subject {
      command('Get-ChildItem -Path Cert:Localmachine\\\\disallowed | Where $_.Issuer -Like
    "*CCEB Interoperability*" | FL Subject,
    Issuer, Thumbprint').stdout
    }
    it { should eq "\r\n\r\nSubject    : CN=DoD Root CA 2, OU=PKI, OU=DoD, O=U.S. Government, C=US\r\nIssuer     : CN=US DoD CCEB Interoperability Root CA 1, OU=PKI, OU=DoD, O=U.S. Government, C=US\r\nThumbprint : DA36FAF56B2F6FBA1604F5BE46D864C9FA013BA3\r\n\r\nSubject    : CN=DoD Root CA 3, OU=PKI, OU=DoD, O=U.S. Government, C=US\r\nIssuer     : CN=US DoD CCEB Interoperability Root CA 2, OU=PKI, OU=DoD, O=U.S. Government, C=US\r\nThumbprint : 929BF3196896994C0A201DF4A5B71F603FEFBF2E\r\n\r\n\r\n\r\n" }
  end
end

