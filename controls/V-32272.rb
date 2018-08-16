control "V-32272" do
  title "The DoD Root CA certificates must be installed in the Trusted Root
  Store."
  desc  "To ensure secure DoD websites and DoD-signed code are properly
  validated, the system must trust the DoD Root Certificate Authorities (CAs).
  The DoD root certificates will ensure that the trust chain is established for
  server certificates issued from the DoD CAs."
  impact 0.5
  tag "gtitle": "WINPK-000001"
  tag "gid": "V-32272"
  tag "rid": "SV-52961r5_rule"
  tag "stig_id": "WN12-PK-000001"
  tag "fix_id": "F-76901r2_fix"
  tag "cci": ["CCI-000185", "CCI-002470"]
  tag "nist": ["SC-23 (5)", "Rev_4"]
  tag "documentable": false
  tag "check": "Verify the DoD Root CA certificates are installed as Trusted
  Root Certification Authorities.

  The certificates and thumbprints referenced below apply to unclassified
  systems; see PKE documentation for other networks.

  Run \"PowerShell\" as an administrator.
  Execute the following command:
  Get-ChildItem -Path Cert:Localmachine\
  oot | Where Subject -Like \"*DoD*\" | FL Subject, Thumbprint
  If the following information is not displayed, this is finding.

  Subject: CN=DoD Root CA 2, OU=PKI, OU=DoD, O=U.S. Government, C=US
  Thumbprint: 8C941B34EA1EA6ED9AE2BC54CF687252B4C9B561

  Subject: CN=DoD Root CA 3, OU=PKI, OU=DoD, O=U.S. Government, C=US
  Thumbprint: D73CA91102A2204A36459ED32213B467D7CE97FB

  Subject: CN=DoD Root CA 4, OU=PKI, OU=DoD, O=U.S. Government, C=US
  Thumbprint: B8269F25DBD937ECAFD4C35A9838571723F2D026

  Alternately use the Certificates MMC snap-in:
  Run \"MMC\".
  Select \"File\", \"Add/Remove Snap-in\".
  Select \"Certificates\", click \"Add\".
  Select \"Computer account\", click \"Next\".
  Select \"Local computer: (the computer this console is running on)\", click
  \"Finish\".
  Click \"OK\".
  Expand \"Certificates\" and navigate to \"Trusted Root Certification
  Authorities >> Certificates\".
  If there are no entries for \"DoD Root CA 2\", \"DoD Root CA 3\", and \"DoD
  Root CA 4\", this is a finding.

  For each of the DoD Root CA certificates noted above:
  Right click on the certificate and select \"Open\".
  Select the \"Details\" Tab.
  Scroll to the bottom and select \"Thumbprint\".

  If the value for the \"Thumbprint\" field is not as noted below, this is a
  finding.
  DoD Root CA 2 - 8C941B34EA1EA6ED9AE2BC54CF687252B4C9B561
  DoD Root CA 3 - D73CA91102A2204A36459ED32213B467D7CE97FB
  DoD Root CA 4 - B8269F25DBD937ECAFD4C35A9838571723F2D026"
  tag "fix": "Install the DoD Root CA certificates.
  DoD Root CA 2
  DoD Root CA 3
  DoD Root CA 4

  The InstallRoot tool is available on IASE at
  http://iase.disa.mil/pki-pke/Pages/tools.aspx."
  describe.one do
    describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\SystemCertificates\\Root\\Certificates\\8C941B34EA1EA6ED9AE2BC54CF687252B4C9B561") do
      it { should exist }
    end
    describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\SystemCertificates\\Root\\Certificates\\D73CA91102A2204A36459ED32213B467D7CE97FB") do
      it { should exist }
    end
    describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\SystemCertificates\\Root\\Certificates\\B8269F25DBD937ECAFD4C35A9838571723F2D026") do
      it { should exist }
    end
    describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\EnterpriseCertificates\\Root\\Certificates\\8C941B34EA1EA6ED9AE2BC54CF687252B4C9B561") do
      it { should exist }
    end
    describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\EnterpriseCertificates\\Root\\Certificates\\D73CA91102A2204A36459ED32213B467D7CE97FB") do
      it { should exist }
    end
    describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\EnterpriseCertificates\\Root\\Certificates\\B8269F25DBD937ECAFD4C35A9838571723F2D026") do
      it { should exist }
    end
    describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\SystemCertificates\\Root\\Certificates\\8C941B34EA1EA6ED9AE2BC54CF687252B4C9B561") do
      it { should exist }
    end
    describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\SystemCertificates\\Root\\Certificates\\D73CA91102A2204A36459ED32213B467D7CE97FB") do
      it { should exist }
    end
    describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\SystemCertificates\\Root\\Certificates\\B8269F25DBD937ECAFD4C35A9838571723F2D026") do
      it { should exist }
    end
    describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\EnterpriseCertificates\\Root\\Certificates\\8C941B34EA1EA6ED9AE2BC54CF687252B4C9B561") do
      it { should exist }
    end
    describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\EnterpriseCertificates\\Root\\Certificates\\D73CA91102A2204A36459ED32213B467D7CE97FB") do
      it { should exist }
    end
    describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\EnterpriseCertificates\\Root\\Certificates\\B8269F25DBD937ECAFD4C35A9838571723F2D026") do
      it { should exist }
    end
  end
end

