control "V-4443" do
  title "Unauthorized remotely accessible registry paths and sub-paths must not
  be configured."
  desc  "The registry is integral to the function, security, and stability of
  the Windows system.  Some processes may require remote access to the registry.
  This setting controls which registry paths and sub-paths are accessible from a
  remote computer.  These registry paths must be limited, as they could give
  unauthorized individuals access to the registry."
  impact 0.7
  tag "gtitle": "Remotely Accessible Registry Paths and Sub-Paths"
  tag "gid": "V-4443"
  tag "rid": "SV-52931r2_rule"
  tag "stig_id": "WN12-SO-000057"
  tag "fix_id": "F-45857r2_fix"
  tag "cci": ["CCE-25426-8", "CCI-001090"]
  tag "nist": ["SC-4", "Rev_4"]
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding:

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path:
  \\System\\CurrentControlSet\\Control\\SecurePipeServers\\Winreg\\AllowedPaths\\

  Value Name: Machine

  Value Type: REG_MULTI_SZ
  Value: see below

  Software\\Microsoft\\OLAP Server
  Software\\Microsoft\\Windows NT\\CurrentVersion\\Perflib
  Software\\Microsoft\\Windows NT\\CurrentVersion\\Print
  Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows
  System\\CurrentControlSet\\Control\\ContentIndex
  System\\CurrentControlSet\\Control\\Print\\Printers
  System\\CurrentControlSet\\Control\\Terminal Server
  System\\CurrentControlSet\\Control\\Terminal Server\\UserConfig
  System\\CurrentControlSet\\Control\\Terminal Server\\DefaultUserConfiguration
  System\\CurrentControlSet\\Services\\Eventlog
  System\\CurrentControlSet\\Services\\Sysmonlog

  Legitimate applications may add entries to this registry value. If an
  application requires these entries to function properly and is documented with
  the ISSO, this would not be a finding.  Documentation must contain supporting
  information from the vendor's instructions."
  tag "fix": "Configure the policy value for Computer Configuration -> Windows
  Settings -> Security Settings -> Local Policies -> Security Options ->
  \"Network access: Remotely accessible registry paths and sub-paths\" with the
  following entries:

  Software\\Microsoft\\OLAP Server
  Software\\Microsoft\\Windows NT\\CurrentVersion\\Perflib
  Software\\Microsoft\\Windows NT\\CurrentVersion\\Print
  Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows
  System\\CurrentControlSet\\Control\\ContentIndex
  System\\CurrentControlSet\\Control\\Print\\Printers
  System\\CurrentControlSet\\Control\\Terminal Server
  System\\CurrentControlSet\\Control\\Terminal Server\\UserConfig
  System\\CurrentControlSet\\Control\\Terminal Server\\DefaultUserConfiguration
  System\\CurrentControlSet\\Services\\Eventlog
  System\\CurrentControlSet\\Services\\Sysmonlog"

  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\SecurePipeServers\\Winreg\\AllowedExactPaths") do
    it { should have_property "Machine" }
  end
  
    describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\SecurePipeServers\\Winreg\\AllowedPaths") do
      its("Machine") { should include "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows"}
    end
    describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\SecurePipeServers\\Winreg\\AllowedPaths") do
      its("Machine") { should include "System\\CurrentControlSet\\Control\\Print\\Printers"}
    end
    describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\SecurePipeServers\\Winreg\\AllowedPaths") do
      its("Machine") { should include "System\\CurrentControlSet\\Services\\Eventlog"}
    end
    describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\SecurePipeServers\\Winreg\\AllowedPaths") do
      its("Machine") { should include "Software\\Microsoft\\OLAP Server"}
    end
    describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\SecurePipeServers\\Winreg\\AllowedPaths") do
      its("Machine") { should include "Software\\Microsoft\\Windows NT\\CurrentVersion\\Print"}
    end
    describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\SecurePipeServers\\Winreg\\AllowedPaths") do
      its("Machine") { should include "System\\CurrentControlSet\\Control\\ContentIndex"}
    end
    describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\SecurePipeServers\\Winreg\\AllowedPaths") do
      its("Machine") { should include "System\\CurrentControlSet\\Control\\Terminal Server"}
    end
    describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\SecurePipeServers\\Winreg\\AllowedPaths") do
      its("Machine") { should include "System\\CurrentControlSet\\Control\\Terminal Server\\UserConfig"}
    end
    describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\SecurePipeServers\\Winreg\\AllowedPaths") do
      its("Machine") { should include "System\\CurrentControlSet\\Control\\Terminal Server\\DefaultUserConfiguration"}
    end
    describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\SecurePipeServers\\Winreg\\AllowedPaths") do
      its("Machine") { should include "Software\\Microsoft\\Windows NT\\CurrentVersion\\Perflib"}
    end
    describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\SecurePipeServers\\Winreg\\AllowedPaths") do
      its("Machine") { should include "System\\CurrentControlSet\\Services\\SysmonLog"}
    end
end

