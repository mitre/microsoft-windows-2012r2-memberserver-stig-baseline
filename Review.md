| Check          | Sub-check                                                                         | Who | Completion Date | Issue #'s |
|----------------|-----------------------------------------------------------------------------------|-----|-----------------|-----------|
|Logical checks| Proper profile directory structure							|Dan Haynes|*|17|
||JSON output review (e.g., pass/fail on ,<br>hardened, not hardened, edge cases, etc.)|*|*|*|
||InSpec syntax checker|Dan Haynes|*|*|
||Local commands focused on target not the runner|Dan Haynes|10/26/2018|*|
|Quality checks|Alignment (including tagging) to original<br> standard (i.e. STIG, CIS Benchmark, NIST Tags)|*|*|*|
||Descriptive output for findings details|*|*|*|
||Documentation quality (i.e. README)<br> novice level instructions including prerequisites|*|*|*|
||Consistency across other profile conventions |*|*|*|
||Spelling grammar|Dan Haynes|*|*|
||Removing debugging documentation and code|Dan Haynes|*|*|
| Error handling |“Profile Error” containment: “null” responses <br>should only happen if InSpec is run with incorrect privileges|*|*|*|
||Slowing the target (e.g. filling up disk, CPU spikes)|Dan Haynes|*|*|
||Check for risky commands (e.g. rm, del, purge, etc.)|Eugene Aronne|11/16/2018|*|
||Check for “stuck” situations (e.g., profile goes on forever)|Dan Haynes|*|*|
