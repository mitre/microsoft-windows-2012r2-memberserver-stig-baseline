control "V-39331" do
  title "The Active Directory SYSVOL directory must have the proper access
control permissions."
  desc  "Improper access permissions for directory data files could allow
unauthorized users to read, modify, or delete directory data.

    The SYSVOL directory contains public files (to the domain) such as policies
and logon scripts.  Data in shared subdirectories are replicated to all domain
controllers in a domain."
  impact 0.7
  tag 'severity': nil
  tag 'gtitle': 'WINAD-000002-DC'
  tag 'gid': 'V-39331'
  tag 'rid': 'SV-51176r2_rule'
  tag 'stig_id': 'WN12-AD-000002-DC'
  tag 'fix_id': 'F-44333r1_fix'
  tag 'cci': ["CCI-002235"]
  tag 'nist': ["AC-6 (10)", "Rev_4"]
  tag 'false_negatives': nil
  tag 'false_positives': nil
  tag 'documentable': false
  tag 'mitigations': nil
  tag 'severity_override_guidance': false
  tag 'potential_impacts': nil
  tag 'third_party_tools': nil
  tag 'mitigation_controls': nil
  tag 'responsibility': nil
  tag 'ia_controls': "ECCD-1, ECCD-2"
  tag 'check': "Verify the permissions on the SYSVOL directory.

Open a command prompt.
Run \"net share\".
Make note of the directory location of the SYSVOL share.

By default this will be \\Windows\\SYSVOL\\sysvol.  For this requirement,
permissions will be verified at the first SYSVOL directory level.

Open File Explorer.
Navigate to \\Windows\\SYSVOL (or the directory noted previously if different).
Right click the directory and select properties.
Select the Security tab.
Click Advanced.

If any standard user accounts or groups have greater than read & execute
permissions, this is a finding. The default permissions noted below meet this
requirement.

Type - Allow
Principal - Authenticated Users
Access - Read & execute
Inherited from - None
Applies to - This folder, subfolder and files

Type - Allow
Principal - Server Operators
Access - Read & execute
Inherited from - None
Applies to - This folder, subfolder and files

Type - Allow
Principal - Administrators
Access - Special
Inherited from - None
Applies to - This folder only
(Access - Special - Basic Permissions: all selected except Full control)

Type - Allow
Principal - CREATOR OWNER
Access - Full control
Inherited from - None
Applies to - Subfolders and files only

Type - Allow
Principal - Administrators
Access - Full control
Inherited from - None
Applies to - Subfolders and files only

Type - Allow
Principal - SYSTEM
Access - Full control
Inherited from - None
Applies to - This folder, subfolders and files


Alternately, use Icacls.exe to view the permissions of the SYSVOL directory.
Open a command prompt.
Run \"icacls c:\\Windows\\SYSVOL
The following results should be displayed:

NT AUTHORITY\\Authenticated Users:(RX)
NT AUTHORITY\\Authenticated Users:(OI)(CI)(IO)(GR,GE)
BUILTIN\\Server Operators:(RX)
BUILTIN\\Server Operators:(OI)(CI)(IO)(GR,GE)
BUILTIN\\Administrators:(M,WDAC,WO)
BUILTIN\\Administrators:(OI)(CI)(IO)(F)
NT AUTHORITY\\SYSTEM:(F)
NT AUTHORITY\\SYSTEM:(OI)(CI)(IO)(F)
BUILTIN\\Administrators:(M,WDAC,WO)
CREATOR OWNER:(OI)(CI)(IO)(F)

(RX) - Read & execute
Run \"icacls /help\" to view definitions of other permission codes."
  tag 'fix': "Ensure the permissions on SYSVOL directory do not allow greater
than read & execute for standard user accounts or groups.  The defaults below
meet this requirement.

Type - Allow
Principal - Authenticated Users
Access - Read & execute
Inherited from - None
Applies to - This folder, subfolder and files

Type - Allow
Principal - Server Operators
Access - Read & execute
Inherited from - None
Applies to - This folder, subfolder and files

Type - Allow
Principal - Administrators
Access - Special
Inherited from - None
Applies to - This folder only
(Access - Special - Basic Permissions: all selected except Full control)

Type - Allow
Principal - CREATOR OWNER
Access - Full control
Inherited from - None
Applies to - Subfolders and files only

Type - Allow
Principal - Administrators
Access - Full control
Inherited from - None
Applies to - Subfolders and files only

Type - Allow
Principal - SYSTEM
Access - Full control
Inherited from - None
Applies to - This folder, subfolders and files"

domain_role = command('wmic computersystem get domainrole | Findstr /v DomainRole').stdout.strip
  if domain_role == '4' || domain_role == '5'
   sysvol_perm = json( command: "icacls 'c:\\Windows\\SYSVOL' | ConvertTo-Json").params.map { |e| e.strip }[0..-3].map{ |e| e.gsub("c:\\Windows\\SYSVOL ", '') }
   
    describe "c:\\ permissions are set correctly on folder structure" do
      subject { sysvol_perm.eql? input('c_windows_sysvol_perm') }
      it { should eq true }
    end
  else
    describe 'This system is not a domain controller, therefore this control is not applicable as it only applies to domain controllers' do
      skip 'This system is not a domain controller, therefore this control is not applicable as it only applies to domain controllers'
    end
  end
end