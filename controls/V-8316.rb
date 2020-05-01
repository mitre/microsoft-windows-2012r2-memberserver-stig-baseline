# -*- encoding : utf-8 -*-
# frozen_string_literal: true

control 'V-8316' do
  title "Active Directory data files must have proper access control
permissions."
  desc  "Improper access permissions for directory data related files could
allow unauthorized users to read, modify, or delete directory data or audit
trails."
  impact 0.7
  tag 'severity:' 'nil'
  tag 'gtitle:' 'Data File Access Permissions'
  tag 'gid:' 'V-8316'
  tag 'rid:' 'SV-51175r3_rule'
  tag 'stig_id:' 'WN12-AD-000001-DC'
  tag 'fix_id:' 'F-80453r1_fix'
  tag 'cci:' '["CCI-002235"]'
  tag 'nist:' '["AC-6 (10)", "Rev_4"]'
  tag 'false_negatives:' 'nil'
  tag 'false_positives:' 'nil'
  tag 'documentable:' 'false'
  tag 'mitigations:' 'nil'
  tag 'severity_override_guidance:' 'false'
  tag 'potential_impacts:' 'nil'
  tag 'third_party_tools:' 'nil'
  tag 'mitigation_controls:' 'nil'
  tag 'responsibility:' 'nil'
  tag 'ia_controls:' 'nil'
  tag 'check:' "Verify the permissions on the content of the NTDS directory.

Open the registry editor (regedit).
Navigate to
HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\NTDS\\Parameters.
Note the directory locations in the values for:
Database log files path
DSA Database file

By default they will be \\Windows\\NTDS. If the locations are different, the
following will need to be run for each.

Open an elevated command prompt (Win+x, Command Prompt (Admin)).
Navigate to the NTDS directory (\\Windows\\NTDS by default).
Run \"icacls *.*\".

If the permissions on each file are not at least as restrictive as the
following, this is a finding.

NT AUTHORITY\\SYSTEM:(I)(F)
BUILTIN\\Administrators:(I)(F)

(I) - permission inherited from parent container
(F) - full access

Do not use File Explorer to attempt to view permissions of the NTDS folder.
Accessing the folder through File Explorer will change the permissions on the
folder."
  tag 'fix:' "Ensure the permissions on NTDS database and log files are at least
as restrictive as the following:
NT AUTHORITY\\SYSTEM:(I)(F)
BUILTIN\\Administrators:(I)(F)

(I) - permission inherited from parent container
(F) - full access"

  domain_role = command('wmic computersystem get domainrole | Findstr /v DomainRole').stdout.strip
  if domain_role == '4' || domain_role == '5'
    # Command Gets the Location of the Property Required
    ntds_database_logs_files_path = json(command: 'Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\NTDS\\Parameters | Select-Object -ExpandProperty "Database log files path" | ConvertTo-Json').params
    # Command Gets Permissions on Folder Path
    icacls_permissions_ntds_folder = json(command: "icacls '#{ntds_database_logs_files_path}' | ConvertTo-Json").params.map(&:strip)[0..-3].map { |e| e.gsub("#{ntds_database_logs_files_path} ", '') }
    # Command Gets the Location of the Property Required
    ntds_dsa_file_path = json(command: 'Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\NTDS\\Parameters | Select-Object -ExpandProperty "DSA Database file" | ConvertTo-Json').params
    # Command Gets Permissions on file ntds.dit
    icacls_permissions_ntds_dsa_file = json(command: "icacls '#{ntds_dsa_file_path}' | ConvertTo-Json").params.map(&:strip)[0..-3].map { |e| e.gsub("#{ntds_dsa_file_path} ", '') }
    describe 'Permissions on NTDS Database Log Files Path is set to' do
      subject { (icacls_permissions_ntds_folder - input('ntds_permissions')).empty? }
      it { should eq true }
    end
    describe 'Permissions on NTDS Database DSA File is set to' do
      subject { (icacls_permissions_ntds_dsa_file - input('ntds_permissions')).empty? }
      it { should eq true }
    end
  else
    describe 'This system is not a domain controller, therefore this control is not applicable as it only applies to domain controllers' do
      skip 'This system is not a domain controller, therefore this control is not applicable as it only applies to domain controllers'
    end
   end
end
