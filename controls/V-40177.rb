control "V-40177" do
  title "Permissions for program file directories must conform to minimum
  requirements."
  desc  "Changing the system's file and directory permissions allows the
  possibility of unauthorized and anonymous modification to the operating system
  and installed applications.

      The default permissions are adequate when the Security Option \"Network
  access: Let everyone permissions apply to anonymous users\" is set to
  \"Disabled\" (V-3377).
  "
  impact 0.5
  tag "gtitle": "WNGE-000007"
  tag "gid": "V-40177"
  tag "rid": "SV-52135r3_rule"
  tag "stig_id": "WN12-GE-000007"
  tag "fix_id": "F-45161r1_fix"
  tag "cci": ["CCI-002165"]
  tag "nist": ['AC-3 (4)', 'Rev_4']
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
  tag "check": "The default permissions are adequate when the Security Option
  \"Network access: Let everyone permissions apply to anonymous users\" is set to
  \"Disabled\" (V-3377).  If the default ACLs are maintained and the referenced
  option is set to \"Disabled\", this is not a finding.

  Verify the default permissions for the program file directories (Program Files
  and Program Files (x86)).  Nonprivileged groups such as Users or Authenticated
  Users must not have greater than Read & execute permissions except where noted
  as defaults.  (Individual accounts must not be used to assign permissions.)

  Viewing in File Explorer:
  For each folder, view the Properties.
  Select the \"Security\" tab, and the \"Advanced\" button.

  Default Permissions:
  \\Program Files and \\Program Files (x86)
  Type - \"Allow\" for all
  Inherited from - \"None\" for all

  Principal - Access - Applies to

  TrustedInstaller - Full control - This folder and subfolders
  SYSTEM - Modify - This folder only
  SYSTEM - Full control - Subfolders and files only
  Administrators - Modify - This folder only
  Administrators - Full control - Subfolders and files only
  Users - Read & execute - This folder, subfolders and files
  CREATOR OWNER - Full control - Subfolders and files only
  ALL APPLICATION PACKAGES - Read & execute - This folder, subfolders and files

  Alternately, use Icacls:

  Open a Command prompt (admin).
  Enter icacls followed by the directory:

  icacls \"c:\\program files\"
  icacls \"c:\\program files (x86)\"

  The following results should be displayed as each is entered:

  c:\\program files
  NT SERVICE\\TrustedInstaller:(F)
  NT SERVICE\\TrustedInstaller:(CI)(IO)(F)
  NT AUTHORITY\\SYSTEM:(M)
  NT AUTHORITY\\SYSTEM:(OI)(CI)(IO)(F)
  BUILTIN\\Administrators:(M)
  BUILTIN\\Administrators:(OI)(CI)(IO)(F)
  BUILTIN\\Users:(RX)
  BUILTIN\\Users:(OI)(CI)(IO)(GR,GE)
  CREATOR OWNER:(OI)(CI)(IO)(F)
  APPLICATION PACKAGE AUTHORITY\\ALL APPLICATION PACKAGES:(RX)
  APPLICATION PACKAGE AUTHORITY\\ALL APPLICATION PACKAGES:(OI)(CI)(IO)(GR,GE)
  Successfully processed 1 files; Failed processing 0 files"
  tag "fix": "Maintain the default permissions for the program file directories
  and configure the Security Option: \"Network access: Let everyone permissions
  apply to anonymous users\" to \"Disabled\" (V-3377).

  Default Permissions:
  \\Program Files and \\Program Files (x86)
  Type - \"Allow\" for all
  Inherited from - \"None\" for all

  Principal - Access - Applies to

  TrustedInstaller - Full control - This folder and subfolders
  SYSTEM - Modify - This folder only
  SYSTEM - Full control - Subfolders and files only
  Administrators - Modify - This folder only
  Administrators - Full control - Subfolders and files only
  Users - Read & execute - This folder, subfolders and files
  CREATOR OWNER - Full control - Subfolders and files only
  ALL APPLICATION PACKAGES - Read & execute - This folder, subfolders and files"
  describe command('Get-Acl -Path "C:\\Program Files" | Format-List | Findstr All | Findstr /V 2') do
    its('stdout') { should eq "         NT AUTHORITY\\SYSTEM Allow  Modify, Synchronize\r\n         BUILTIN\\Administrators Allow  Modify, Synchronize\r\n         BUILTIN\\Users Allow  ReadAndExecute, Synchronize\r\n         NT SERVICE\\TrustedInstaller Allow  FullControl\r\n         APPLICATION PACKAGE AUTHORITY\\ALL APPLICATION PACKAGES Allow  ReadAndExecute, Synchronize\r\n" }
  end
  describe command('Get-Acl -Path "C:\\Program Files" | Format-List | Findstr All | Findstr CREATOR') do
    its('stdout') { should eq "Access : CREATOR OWNER Allow  268435456\r\n" }
  end

  describe command('Get-Acl -Path "C:\\Program Files (x86)" | Format-List | Findstr All | Findstr /V 2') do
    its('stdout') { should eq "         NT AUTHORITY\\SYSTEM Allow  Modify, Synchronize\r\n         BUILTIN\\Administrators Allow  Modify, Synchronize\r\n         BUILTIN\\Users Allow  ReadAndExecute, Synchronize\r\n         NT SERVICE\\TrustedInstaller Allow  FullControl\r\n         APPLICATION PACKAGE AUTHORITY\\ALL APPLICATION PACKAGES Allow  ReadAndExecute, Synchronize\r\n" }
  end
  describe command('Get-Acl -Path "C:\\Program Files (x86)" | Format-List | Findstr All | Findstr CREATOR') do
    its('stdout') { should eq "Access : CREATOR OWNER Allow  268435456\r\n" }
  end
end

