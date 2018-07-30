control "V-1135" do
  title "Nonadministrative user accounts or groups must only have print
permissions on printer shares."
  desc  "Windows shares are a means by which files, folders, printers, and
other resources can be published for network users to access.  Improper
configuration can permit access to devices and data beyond a user's need."
  impact 0.3
  tag "gtitle": "Printer Share Permissions"
  tag "gid": "V-1135" 
  tag "rid": "SV-52213r1_rule"
  tag "stig_id": "WN12-GE-000012"
  tag "fix_id": "F-45232r1_fix"
  tag "cci": ["CCI-000213"]
  tag "nist": ["CCI-000213"]
  tag "nist": ["AC-3", "Rev_4"]
  tag "documentable": false
  tag "check": "Open \"Devices and Printers\" in Control Panel or through
  Search.
  If there are no printers configured, this is NA.

  For each configured printer:
  Right click on the printer.
  Select \"Printer Properties\".
  Select the \"Sharing\" tab.
  View whether \"Share this printer\" is checked.

  For any printers with \"Share this printer\" selected:
  Select the Security tab.

  If any standard user accounts or groups have permissions other than \"Print\",
  this is a finding.
  Standard users will typically be given \"Print\" permission through the
  Everyone group.
  \"All APPLICATION PACKAGES\" and \"CREATOR OWNER\" are not considered standard
  user accounts for this requirement."
  tag "fix": "Configure the permissions on shared printers to restrict standard
  users to  only have Print permissions.  This is typically given through the
  Everyone group by default."
  get_shared_printer_status = command('get-Printer | Format-List | Findstr Shared').stdout.strip.split("\n")
  get_shared_printer_status.each do |status|
    loc_colon = status.index(':')
    shared = status[loc_colon+2..loc_colon+7]

    if (shared == 'False')
      describe "Printer shared not enabled" do
        skip "control not applicable"
      end
    end
  end
end

