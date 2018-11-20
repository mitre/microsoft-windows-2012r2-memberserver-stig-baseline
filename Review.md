| Check          | Sub-check                                                                         | Who | Completion Date | Issue #'s |
|----------------|-----------------------------------------------------------------------------------|-----|-----------------|-----------|
|Logical checks| Proper profile directory structure	[1]						|Dan Haynes (reviewed all controls)|*|17|
||JSON output review (e.g., pass/fail on ,<br>hardened, not hardened, edge cases, etc.)|*|*|*|
||InSpec syntax checker|Dan Haynes|*|1, 15|
||Local commands focused on target not the runner [2]|Dan Haynes (reviewed all controls)|10/26/2018|*|
|Quality checks|Alignment (including tagging) to original<br> standard (i.e. STIG, CIS Benchmark, NIST Tags)|*|*|*|
||Descriptive output for findings details|Dan Haynes|*|*|
||Documentation quality (i.e. README)<br> novice level instructions including prerequisites|*|*|*|
||Consistency across other profile conventions |*|*|*|
||Spelling, grammar,linting (e.g., rubocop, etc.)|Dan Haynes (reviewed all controls)|*|4|
||Removing debugging documentation and code|Dan Haynes (reviewed all controls)|*|*|
| Error handling |“Profile Error” containment: “null” responses <br>should only happen if InSpec is run with incorrect privileges|Dan Haynes|*|*|
||Slowing the target (e.g. filling up disk, CPU spikes)|Dan Haynes (reviewed all controls)|*|*|
||Check for risky commands (e.g. rm, del, purge, etc.)|Eugene Aronne|11/16/2018|*|
||Check for “stuck” situations (e.g., profile goes on forever)|Dan Haynes (reviewed all controls)|*|*|


[1] https://www.inspec.io/docs/reference/profiles/
[2] https://www.inspec.io/docs/reference/style/ (see "Avoid Shelling Out")
