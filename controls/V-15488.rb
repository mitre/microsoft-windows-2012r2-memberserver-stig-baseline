control "V-15488" do
  title "Active directory user accounts, including administrators, must be
configured to require the use of a Common Access Card (CAC), PIV-compliant
hardware token, or Alternate Logon Token (ALT) for user authentication."
  desc  "Smart cards such as the Common Access Card (CAC) support a two-factor
authentication technique.  This provides a higher level of trust in the
asserted identity than use of the username and password for authentication."
  impact 0.5
  tag 'severity': nil
  tag 'gtitle': 'PKI Authentication Req'
  tag 'gid': 'V-15488'
  tag 'rid': 'SV-51192r4_rule'
  tag 'stig_id': 'WN12-PK-000008-DC'
  tag 'fix_id': 'F-71587r2_fix'
  tag 'cci': ["CCI-000765", "CCI-000766", "CCI-000767", "CCI-000768",
"CCI-001948"]
  tag 'nist': ["IA-2 (1)", "IA-2 (2)", "IA-2 (3)", "IA-2 (4)", "IA-2 (11)",
"Rev_4"]
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
  tag 'check': "Verify active directory user accounts, including administrators,
have \"Smart card is required for interactive logon\" selected.

Run \"PowerShell\".
Enter the following:
\"Get-ADUser -Filter {(Enabled -eq $True) -and (SmartcardLogonRequired -eq
$False)} | FT Name\"
(\"DistinguishedName\" may be substituted for \"Name\" for more detailed
output.)
If any user accounts are listed, this is a finding.

Alternately:
To view sample accounts in \"Active Directory Users and Computers\" (Available
from various menus or run \"dsa.msc\"):
Select the Organizational Unit (OU) where the User accounts are located.  (By
default this is the Users node; however, accounts may be under other
organization-defined OUs.)
Right click the sample User account and select \"Properties\".
Select the \"Account\" tab.
If any User accounts do not have \"Smart card is required for interactive
logon\" checked in the \"Account Options\" area, this is a finding."
  tag 'fix': "Configure all user accounts, including administrator accounts, in
Active Directory to enable the option \"Smart card is required for interactive
logon\".

Run \"Active Directory Users and Computers\" (Available from various menus or
run \"dsa.msc\"):
Select the Organizational Unit (OU) where the user accounts are located.  (By
default this is the Users node; however, accounts may be under other
organization-defined OUs.)
Right click the user account and select \"Properties\".
Select the \"Account\" tab.
Check \"Smart card is required for interactive logon\" in the \"Account
Options\" area."

domain_role = command('wmic computersystem get domainrole | Findstr /v DomainRole').stdout.strip
 if domain_role == '4' || domain_role == '5'
  query = json(command: 'Get-ADUser -Filter * -Properties SmartcardLogonRequired  | Where-Object {$_.Enabled -eq "True" -and $_.SmartcardLogonRequired -like "False"} | Select -ExpandProperty Name | ConvertTo-Json').params
   describe 'Accounts' do
          subject { query }
          it 'All Accounts on Domain should use Smart card is required for interactive logon' do
          failure_message = "Accounts Listed Below are set up wrong: #{query}"
          expect(query).to be_empty, failure_message
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
