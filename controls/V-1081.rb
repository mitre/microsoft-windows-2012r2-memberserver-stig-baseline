control "V-1081" do
  title "Local volumes must use a format that supports NTFS attributes."
  desc  "The ability to set access permissions and auditing is critical to
  maintaining the security and proper access controls of a system. To support
  this, local volumes must be formatted using a file system that supports NTFS
  attributes."
  impact 0.7
  tag "gtitle": "NTFS Requirement"
  tag "gid": "V-1081"
  tag "rid": "SV-52843r3_rule"
  tag "stig_id": "WN12-GE-000005"
  tag "fix_id": "F-81015r1_fix"
  tag "cci": ["CCI-000213"]
  tag "nist": ["CCI-000213"]
  tag "nist": ["AC-3", "Rev_4"]
  tag "documentable": false
  tag "check": "Open \"Computer Management\".

  Select \"Disk Management\" under \"Storage\".

  For each local volume, if the file system does not indicate \"NTFS\", this is a
  finding.

  \"ReFS\" (Resilient File System) is also acceptable and would not be a finding.

  This does not apply to system partitions such as the Recovery and EFI System
  Partition."
  tag "fix": "Format local volumes to use NTFS or ReFS."
  get_volumes = command("wmic logicaldisk list /format:list | Findstr FileSystem=").stdout.strip.split("\n")
  
  get_volumes.each do |volume|
      describe.one do
      describe "#{volume}" do
        it { should eq "FileSystem=NTFS\r"}
      end  
      describe "#{volume}" do
        it { should eq "FileSystem=ReFS\r"}
      end
    end
  end
end

