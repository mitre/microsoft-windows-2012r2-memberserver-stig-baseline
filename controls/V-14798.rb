control "V-14798" do
  title "Directory data (outside the root DSE) of a non-public directory must
be configured to prevent anonymous access."
  desc  "To the extent that anonymous access to directory data (outside the
root DSE) is permitted, read access control of the data is effectively
disabled.  If other means of controlling access (such as, network restrictions)
are compromised, there may be nothing else to protect the confidentiality of
sensitive directory data."
  impact 0.7
  tag 'severity': nil
  tag 'gtitle': 'Anonymous Access to Non-Public Data '
  tag 'gid': 'V-14798'
  tag 'rid': 'SV-51187r2_rule'
  tag 'stig_id': 'WN12-AD-000013-DC'
  tag 'fix_id': 'F-44344r2_fix'
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
  tag 'check': "Verify anonymous access is not allowed to the AD domain naming
context.

Open a command prompt (not elevated).
Run \"ldp.exe\".
From the Connection menu, select Bind.
Clear the User, Password, and Domain fields.
Select Simple bind for the Bind type, Click OK.

Confirmation of anonymous access will be displayed at the end:
res = ldap_simple_bind_s
Authenticated as: 'NT AUTHORITY\\ANONYMOUS LOGON'

From the Browse menu, select Search.
In the Search dialog, enter the DN of the domain naming context (generally
something like \"dc=disaost,dc=mil\") in the Base DN field.
Clear the Attributes field and select Run.

Error messages should display related to bind and user not authenticated.

If attribute data is displayed, anonymous access is enabled to the domain
naming context and this is a finding."
  tag 'fix': "Configure directory data (outside the root DSE) of a non-public
directory to prevent anonymous access.

For AD, there are multiple configuration items that could enable anonymous
access.

Changing the access permissions on the domain naming context object (from the
secure defaults) could enable anonymous access.  If the check procedures
indicate this is the cause, the process that was used to change the permissions
should be reversed.  This could have been through the Windows Support Tools
ADSI Edit console (adsiedit.msc).

The dsHeuristics option is used.  This is addressed in check V-8555 in the AD
Forest STIG."

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

