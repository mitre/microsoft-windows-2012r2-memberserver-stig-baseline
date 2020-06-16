control "V-26683" do
  title "PKI certificates associated with user accounts must be issued by the
DoD PKI or an approved External Certificate Authority (ECA)."
  desc  "A PKI implementation depends on the practices established by the
Certificate Authority (CA) to ensure the implementation is secure.  Without
proper practices, the certificates issued by a CA have limited value in
authentication functions."
  impact 0.7
  tag 'severity': nil
  tag 'gtitle': 'Directory PKI Certificate Source - Users'
  tag 'gid': 'V-26683'
  tag 'rid': 'SV-51191r5_rule'
  tag 'stig_id': 'WN12-PK-000007-DC'
  tag 'fix_id': 'F-80469r1_fix'
  tag 'cci': ["CCI-000185"]
  tag 'nist': ["IA-5 (2) (a)", "Rev_4"]
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
  tag 'check': "Open \"PowerShell\" as Administrator.

Enter \"Get-ADUser -Filter * | FT Name, UserPrincipalName, Enabled -AutoSize\".

Review the User Principal Name (UPN) of user accounts, including
administrators.

Exclude the built-in accounts such as Administrator and Guest.

If the User Principal Name (UPN) is not in the format of an individual's
identifier for the certificate type and for the appropriate domain suffix, this
is a finding.

For standard NIPRNET certificates the individual's identifier is in the format
of an Electronic Data Interchange - Personnel Identifier (EDI-PI).

Alt Tokens and other certificates may use a different UPN format than the
EDI-PI, which vary by organization.  Verify these with the organization.

NIPRNET Example:
Name - User Principal Name
User1 - 1234567890@mil

See PKE documentation for other network domain suffixes.

If the mappings are to certificates issued by a CA authorized by the
Component's CIO, this is a CAT II finding."
  tag 'fix': "Map user accounts to PKI certificates using the appropriate User
Principal Name (UPN) for the network. See PKE documentation for details."

  domain_role = command('wmic computersystem get domainrole | Findstr /v DomainRole').stdout.strip

   if domain_role == '4' || domain_role == '5'
     query = json(command: 'Get-ADUser -FIlter * | Where-Object {$_.Enabled -eq "True" } | Select-Object -Property Name, UserPrincipalName | ConvertTo-Json').params
      query.each do |user|
       describe json({ content: user.to_json }) do
        its('UserPrincipalName') { should match(/[\w*]@mil/) }
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

