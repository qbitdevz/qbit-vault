package dumpguard

// Class is the reason a pattern refuses a command. The values are the
// dump_command rule ids of the broker contract (refusal.Rule); a test keeps
// the two sets equal.
type Class string

const (
	EnvironmentDump Class = "environment_dump"
	ValuePrint      Class = "value_print"
	ValueEncode     Class = "value_encode"
	NetworkArgument Class = "network_argument"
	EncodedScript   Class = "encoded_script"
	CustomRule      Class = "custom_rule"
)

// defaultClass is the class of each default pattern, keyed on the exact
// pattern source in default.yaml. The data file format carries no class, so a
// user file keeps loading; a pattern absent here (every user pattern) is
// CustomRule. A test keeps this map and default.yaml in step.
var defaultClass = map[string]Class{
	`^env$`:           EnvironmentDump,
	`^env\s+-\S*0`:    EnvironmentDump,
	`^printenv(\s|$)`: EnvironmentDump,
	`^set$`:           EnvironmentDump,
	`^export\s+-p$`:   EnvironmentDump,
	`^declare\s+-x`:   EnvironmentDump,
	`^typeset\s+-x`:   EnvironmentDump,
	`^(cat|less|more|head|tail|strings|xxd|od)\s+(/proc/(self|\d+)/environ)`: EnvironmentDump,
	// A descriptor can carry a secret handed to a tool by pipe.
	`^(cat|less|more|head|tail)\s+/dev/fd/`:                                   ValuePrint,
	`(?i)^(gci|get-childitem|ls|dir)\s+env:`:                                  EnvironmentDump,
	`(?i)\[environment\]::getenvironmentvariables`:                            EnvironmentDump,
	`(?i)^get-item\s+env:`:                                                    EnvironmentDump,
	`^echo\s+.*\$\{?{NAME}\}?`:                                                ValuePrint,
	`^printf\s+.*\$\{?{NAME}\}?`:                                              ValuePrint,
	`(?i)^(echo|write-output|write-host)\s+.*\$env:{NAME}`:                    ValuePrint,
	`^echo\s+.*%{NAME}%`:                                                      ValuePrint,
	`^(python3?|node|ruby|perl)\s+-[ce]\s+.*(os\.environ|process\.env|ENV\[)`: EnvironmentDump,
	`^node\s+-p\s+process\.env`:                                               EnvironmentDump,
	`(base64|xxd|od|hexdump)\s*<<<\s*"?\$\{?{NAME}`:                           ValueEncode,
	`^(curl|wget|http|nc|ncat|socat)\s+.*\$\{?{NAME}\}?`:                      NetworkArgument,
	`^export$`:                   EnvironmentDump,
	`^(declare|typeset)$`:        EnvironmentDump,
	`^(declare|typeset)\s+-\S*p`: EnvironmentDump,
	// declare -x NAME prints NAME=value.
	`^(declare|typeset)\s+(-\S+\s+)*{NAME}`:                                 ValuePrint,
	`^compgen\s+(-\S*[ev]|-A\s+(variable|export))`:                          EnvironmentDump,
	`/proc/(self|thread-self|\d+|\$\$|\$\{?BASHPID\}?)(/task/\d+)?/environ`: EnvironmentDump,
	`^find\s+.*-(exec|execdir|ok|okdir)\s+(\S*/)?(env|printenv)(\s|;|$)`:    EnvironmentDump,
	// ${!X} reads whichever variable X names, the environment included.
	`\$\{!`:                             EnvironmentDump,
	`<<.*\$\{?{NAME}`:                   ValuePrint,
	`^(awk|gawk|mawk|nawk)\s+.*ENVIRON`: EnvironmentDump,
	`^perl\s+.*(%ENV|\$ENV\s*\{)`:       EnvironmentDump,
	`^(python3?|py)\s+.*(os\.(getenv|environ)|from\s+os\s+import\s+.*(environ|getenv))`: EnvironmentDump,
	`^node\s+.*process\.env`:                                   EnvironmentDump,
	`^ruby\s+.*\bENV\b`:                                        EnvironmentDump,
	`(?i)\$\{?env:{NAME}`:                                      ValuePrint,
	`(?i)^(get-content|gc|cat|type)\s+(-\S+\s+)*env:`:          EnvironmentDump,
	`(?i)\[(system\.)?environment\]::getenvironmentvariable\b`: EnvironmentDump,
	`(?i)^set\s+"?[a-z_][a-z0-9_]*"?$`:                         EnvironmentDump,
	`%{NAME}:[^%\s]*%`:                                         ValuePrint,
}

func classOf(src string) Class {
	if c, ok := defaultClass[src]; ok {
		return c
	}
	return CustomRule
}
