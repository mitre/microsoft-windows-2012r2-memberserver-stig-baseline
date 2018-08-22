# windows_2012r2_memberserver_stig

InSpec profile testing secure configuration of Windows 2012r2 member servers.

## Description

This InSpec compliance profile is a collection of automated tests for secure configuration of Windows 2012r2 Member Server's.

InSpec is an open-source run-time framework and rule language used to specify compliance, security, and policy requirements for testing any node in your infrastructure.

## Requirements

- [ruby](https://www.ruby-lang.org/en/) at least 2.4
- [InSpec](http://inspec.io/) at least version 2.1
    - Install via ruby gem: `gem install inspec`

## Usage
InSpec makes it easy to run tests wherever you need. More options listed here: [InSpec cli](http://inspec.io/docs/reference/cli/)

### Run with remote profile:
You may choose to run the profile via a remote url, this has the advantage of always being up to date.
The disadvantage is you may wish to modify controls, which is only possible when downloaded.
Also, the remote profile is unintuitive for passing in attributes, which modify the default values of the profile.
``` bash
inspec exec https://gitlab.mitre.org/inspec/windows_2012r2_memberserver_stig/repository/master/archive.tar.gz
```

Another option is to download the profile then run it, this allows you to edit specific instructions and view the profile code.
``` bash
# Clone Inspec Profile
$ git clone https://gitlab.mitre.org/inspec/apache_server_baseline.git

# Run profile locally (assuming you have not changed directories since cloning)
# This will display compliance level at the prompt, and generate a JSON file 
# for export called output.json
$ inspec exec windows_2012r2_memberserver_stig --reporter cli json:output.json

# Run profile with custom settings defined in attributes.yml against the target 
# server example.com. 
$ inspec exec windows_2012r2_memberserver_stig -t ssh://user@password:example.com --attrs attributes.yml --reporter cli json:output.json

# Run profile with: custom attributes, ssh keyed into a custom target, and sudo.
$ inspec exec windows_2012r2_memberserver_stig -t ssh://user@hostname -i /path/to/key --sudo --attrs attributes.yml --reporter cli json:output.json
```


## Contributors + Kudos

- Alicia Sturtevant
- The MITRE InSpec Team

## License and Author

### Authors

- Author:: Alicia Sturtevant

### License 

* This project is licensed under the terms of the Apache license 2.0 (apache-2.0)
