# -*- encoding : utf-8 -*-
# frozen_string_literal: true

control 'V-8317' do
  title "Data files owned by users must be on a different logical partition
from the directory server data files."
  desc  "When directory service data files, especially for directories used for
identification, authentication, or authorization, reside on the same logical
partition as user-owned files, the directory service data may be more
vulnerable to unauthorized access or other availability compromises.  Directory
service and user-owned data files sharing a partition may be configured with
less restrictive permissions in order to allow access to the user data.

    The directory service may be vulnerable to a denial of service attack when
user-owned files on a common partition are expanded to an extent preventing the
directory service from acquiring more space for directory or audit data."
  impact 0.5
  tag 'severity': nil
  tag 'gtitle': 'Directory Server Data File Locations'
  tag 'gid': 'V-8317'
  tag 'rid': 'SV-51180r2_rule'
  tag 'stig_id': 'WN12-AD-000006-DC'
  tag 'fix_id': 'F-44337r1_fix'
  tag 'cci': ["CCI-001082"]
  tag 'nist': ["SC-2", "Rev_4"]
  tag 'false_negatives': nil
  tag 'false_positives': nil
  tag 'documentable': false
  tag 'mitigations': nil
  tag 'severity_override_guidance': false
  tag 'potential_impacts': nil
  tag 'third_party_tools': nil
  tag 'mitigation_controls': nil
  tag 'responsibility': nil
  tag 'ia_controls': 'DCSP-1'
  tag 'check': "Refer to the AD database location obtained in check V-8316.  Note
the logical drive (e.g., C:) on which the files are located.

Determine if the server is currently providing file sharing services to users
with the following command.
Enter \"net share\" at a command prompt.

Note the logical drive(s) or file system partition for any site-created data
shares.
Ignore all system shares (e.g., Windows NETLOGON, SYSVOL, and administrative
shares ending in $). User shares that are hidden (ending with $) should not be
ignored.

If user shares are located on the same logical partition as the directory
server data files, this is a finding."
  tag 'fix': "Ensure files owned by users  are stored on a different logical
partition then the directory server data files."

  domain_role = command('wmic computersystem get domainrole | Findstr /v DomainRole').stdout.strip
  if domain_role == '4' || domain_role == '5'
    # Gets the Path of the Database File
    ntds_dsa_file_path = json(command: 'Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\NTDS\\Parameters | Select-Object -ExpandProperty "DSA Database file" | ConvertTo-Json').params[0..2]
    # Adds WildCard to drive Letter
    add_wildcard = (ntds_dsa_file_path.to_s + '*')
    # Adds ' ' to the variable
    add_tics = "('#{add_wildcard}')"
    # Gets Drive Letter Information
    drive_letter = json(command: "Get-SmbShare -Path| Where-Object {$_.Path -like #{add_tics} -and $_.Name -notlike '*$' -and $_.Name -notlike 'NETLOGON' -and $_.Name -notlike 'SYSVOL'} | Select Name | ConvertTo-Json").params

    if drive_letter.empty?
      describe 'File Shares are Set up correctly on AD Database Logical Drive' do
      subject { drive_letter}
      it { should be_empty }
      #describe 'File Shares are Set up correctly on AD Database Logical Drive' do
       # skip 'File Shares are Set up correctly on AD Database Logical Drive'
      end
    elsif
      describe 'File Shares' do
        it 'Extra File Shares are located on Logical Drive' do
          failure_message = "extra shares #{drive_letter}"
          expect(drive_letter).to be_empty, failure_message
        end
      end
    else
      describe 'Server is a Member Server or Standalone, Control V-8317 is NA' do
        skip 'Server is a Member Server or Standalone, Control V-8317 is NA'
      end
   end
 end
end
