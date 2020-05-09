control "V-91777" do
  title "The password for the krbtgt account on a domain must be reset at least
every 180 days."
  desc  "The krbtgt account acts as a service account for the Kerberos Key
Distribution Center (KDC) service. The account and password are created when a
domain is created and the password is typically not changed. If the krbtgt
account is compromised, attackers can create valid Kerberos Ticket Granting
Tickets (TGT).

    The password must be changed twice to effectively remove the password
history.Changing once, waiting for replication to complete and the amount of
time equal to or greater than the maximum Kerberos ticket lifetime, and
changing again reduces the risk of issues."
  impact 0.5
  tag 'severity': nil
  tag 'gtitle': 'WINAD-000015-DC'
  tag 'gid': 'V-91777'
  tag 'rid': 'SV-101879r2_rule'
  tag 'stig_id': 'WN12-AD-000015-DC'
  tag 'fix_id': 'F-97979r1_fix'
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
  tag 'ia_controls': nil
  tag 'check': "This requirement is applicable to domain controllers; it is NA
for other systems.

Open \"Windows PowerShell\".

Enter \"Get-ADUser krbtgt -Property PasswordLastSet\".

If the \"PasswordLastSet\" date is more than 180 days old, this is a finding."
  tag 'fix': "Reset the password for the krbtgt account a least every 180 days.
The password must be changed twice to effectively remove the password history.
Changing once, waiting for replication to complete and changing again reduces
the risk of issues. Changing twice in rapid succession forces clients to
re-authenticate (including application services) but is desired if a compromise
is suspected.

PowerShell scripts are available to accomplish this such as at the following
link:
https://gallery.technet.microsoft.com/Reset-the-krbtgt-account-581a9e51

Open \"Active Directory Users and Computers\" (available from various menus or
run \"dsa.msc\").

Select \"Advanced Features\" in the \"View\" menu if not previously selected.

Select the \"Users\" node.

Right click on the krbtgt account and select \"Reset password\".

Enter a password that meets password complexity requirements.

Clear the \"User must change password at next logon\" check box.

The system will automatically change this to a system generated complex
password."

  describe 'A manual review is required to reset password on account krbtgt' do
    skip 'A manual review is required to reset password on account krbtgt'
  end
 end

