control "V-14797" do
  title "Anonymous access to the root DSE of a non-public directory must be
disabled."
  desc  "Allowing anonymous access to the root DSE data on a directory server
provides potential attackers with a number of details about the configuration
and data contents of a directory.  For example, the namingContexts attribute
indicates the directory space contained in the directory; the
supportedLDAPVersion attribute indicates which versions of the LDAP protocol
the server supports; and the supportedSASLMechanisms attribute indicates the
names of supported authentication mechanisms.  An attacker with this
information may be able to select more precisely targeted attack tools or
higher value targets."
  impact 0.3
  tag 'severity': nil
  tag 'gtitle': 'Anonymous Access to Non-Public Root DSE Data'
  tag 'gid': 'V-14797'
  tag 'rid': 'SV-51186r2_rule'
  tag 'stig_id': 'WN12-AD-000012-DC'
  tag 'fix_id': 'F-44343r1_fix'
  tag 'cci': ["CCI-000366"]
  tag 'nist': ["CM-6 b", "Rev_4"]
  tag 'false_negatives': nil
  tag 'false_positives': nil
  tag 'documentable': false
  tag 'mitigations': nil
  tag 'severity_override_guidance': false
  tag 'potential_impacts': nil
  tag 'third_party_tools': nil
  tag 'mitigation_controls': nil
  tag 'responsibility': nil
  tag 'ia_controls': "ECAN-1, ECCD-1, ECCD-2"
  tag 'check': "At this time, this is a finding for all Windows domain
controllers for sensitive or classified levels as Windows Active Directory
Domain Services (AD DS) does not provide a method to restrict anonymous access
to the root DSE on domain controllers.

The following can be used to verify anonymous access is allowed.

Open a command prompt (not elevated).
Run \"ldp.exe\".
From the Connection menu, select Bind.
Clear the User, Password, and Domain fields.
Select Simple bind for the Bind type, Click OK.

RootDSE attributes should display, such as various namingContexts.

Confirmation of anonymous access will be displayed at the end:
res = ldap_simple_bind_s
Authenticated as: 'NT AUTHORITY\\ANONYMOUS LOGON'"
  tag 'fix': "Implement network protections to reduce the risk of anonymous
access.

Network hardware ports at the site are subject to 802.1x authentication or MAC
address restrictions.

Premise firewall or host restrictions prevent access to ports 389, 636, 3268,
and 3269 from client hosts not explicitly identified by domain (.mil) or IP
address."

 domain_role = command('wmic computersystem get domainrole | Findstr /v DomainRole').stdout.strip
  if domain_role == '4' || domain_role == '5'
     describe 'Directory data (outside the root DSE) of a non-public directory must be configured to prevent anonymous access.' do
      skip 'Directory data (outside the root DSE) of a non-public directory must be configured to prevent anonymous access is a manual control'
     end
  else
    impact 0.0
    desc 'This system is not a domain controller, therefore this control is not applicable as it only applies to domain controllers'
    describe 'This system is not a domain controller, therefore this control is not applicable as it only applies to domain controllers' do
      skip 'This system is not a domain controller, therefore this control is not applicable as it only applies to domain controllers'
    end
  end
end

