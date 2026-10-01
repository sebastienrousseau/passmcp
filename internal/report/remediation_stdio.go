// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package report

// stdioRemediations is the guidance for the checks only a child-process
// run can make, including what the sandbox saw it touch.
var stdioRemediations = map[string]Remediation{
	// --- stdio: the checks that only a child-process run can make ---------

	"stdio.clean_exit": {
		Means: "The server was still running after its stdin closed, and had " +
			"to be signalled. Closing the pipe is how a host ends a stdio " +
			"session — it is the documented shutdown and there is no other " +
			"one — so a server that carries on is a server the host has to " +
			"kill, every session, forever.",
		Steps: []Step{
			{"Treat EOF on stdin as the stop signal",
				"The read loop returning end-of-file is the session ending. " +
					"Finish what is in flight, flush, and exit; do not wait " +
					"for a signal that a well-behaved host will not send " +
					"first."},
			{"Handle SIGTERM as well, not instead",
				"A host that has waited its grace period signals before it " +
					"kills. A server that ignores both loses whatever it had " +
					"not written."},
			{"Count the processes after a few sessions",
				"This is the defect that shows up as a developer machine with " +
					"eleven copies of the same server on it, none of which any " +
					"host still has a handle to."},
		},
	},

	"stdio.no_zombie": {
		Means: "The server exited and processes it had started were still " +
			"running in its process group. Nothing else in the report " +
			"notices: the server handshook, served its catalogue and shut " +
			"down cleanly. The worker it left behind still holds what it was " +
			"given — a port, a lock, the credentials from its environment — " +
			"and there is no longer anything that knows how to stop it.",
		Steps: []Step{
			{"Reap what you spawn",
				"Keep a handle on every child and wait for it during " +
					"shutdown. A worker started for one session should not " +
					"outlive that session."},
			{"Kill the group, not the leader",
				"If the children are not tracked individually, put them in a " +
					"process group and signal the group on the way out."},
			{"Do not rely on the host",
				"passmcp killed this one, because leaving it running would be a " +
					"worse defect than reporting it. A host will not: it closes " +
					"the pipe and forgets the server existed."},
		},
		Note: "Only asked when the server exited on its own. If it had to be " +
			"signalled, its whole group went with it and what it left behind " +
			"cannot be told apart from what the signal stopped, so the check " +
			"skips rather than guessing. Platforms without POSIX process " +
			"groups skip it too.",
	},

	"supply.provenance": {
		Means: "The server binary was built from a working tree with " +
			"uncommitted changes. Go records that as `vcs.modified=true`, " +
			"and it means the source this binary was made from does not " +
			"exist in the repository: no commit describes it, so no review " +
			"of that repository describes what is actually running.",
		Steps: []Step{
			{"Build from a clean checkout",
				"In CI that is usually already true. A dirty stamp on a " +
					"release artifact almost always means it was built on " +
					"somebody's laptop."},
			{"Keep the revision",
				"A binary built from a commit carries it, and that one field " +
					"is what turns \"we reviewed the code\" into a statement " +
					"about the thing that is running."},
			{"Where dependencies carry no checksum, find out why",
				"A module with no `h1:` sum did not come through the module " +
					"proxy and the checksum database never saw it — a local " +
					"`replace` or a vendored tree. Neither can be verified " +
					"after the fact."},
		},
		Note: "Read out of the binary with `debug/buildinfo`, so it is one " +
			"of the few things in this report the server cannot influence by " +
			"answering differently. Only for a stdio target: an endpoint is a " +
			"URL, and a URL is not a file passmcp can open. A build from a " +
			"source archive carries no stamp at all, which is reported as an " +
			"observation rather than as a dirty build.",
	},

	"fs.credential_probe": {
		Means: "The server opened a credential file in its home directory " +
			"that it was never given and never asked about. passmcp planted " +
			"those files: they are decoys containing nothing real, and the " +
			"home directory the server saw was a scratch one. Nothing was " +
			"lost here. The same code against an operator's own machine " +
			"reads their actual keys.",
		Steps: []Step{
			{"Find the read",
				"The finding names which decoys were opened. A server that " +
					"reads ~/.ssh/id_rsa or ~/.aws/credentials has a code path " +
					"that goes looking for credentials outside the ones it was " +
					"configured with, and that path is worth reading."},
			{"Ask whether it is a library",
				"Some SDKs load ambient cloud credentials by default. That is " +
					"still a server reaching for something nobody gave it, and " +
					"it still deserves to be deliberate rather than a default " +
					"nobody noticed."},
			{"Check what left",
				"`fs.canary_exfiltrated` answers the second half. A read with " +
					"nothing leaving is a smaller problem than a read followed " +
					"by a request."},
		},
		Note: "This rests on file access times, and a great many filesystems " +
			"do not record them — macOS on APFS does not, and Linux mounted " +
			"`noatime` does not. passmcp measures whether the witness works " +
			"before trusting it and reports that it cannot tell rather than " +
			"reporting a clean result it is not entitled to.",
	},

	"fs.canary_exfiltrated": {
		Means: "The contents of a planted credential file left. This is not " +
			"an inference: each decoy contains a string that exists nowhere " +
			"else, and that exact string was seen in an outbound request " +
			"body, on the server's own stderr, or handed back to passmcp in a " +
			"result. The file was read and its contents were sent.",
		Steps: []Step{
			{"Treat it as an incident, not a finding",
				"Whatever reads a decoy key and transmits it reads a real one " +
					"and transmits that. The finding names the file and where " +
					"the contents went."},
			{"Find the code before the server runs anywhere real",
				"It may be deliberate, it may be a logging statement that " +
					"dumps an environment, and the two are not the same " +
					"problem — but both send a credential somewhere it does " +
					"not belong."},
			{"Assume any real credential is compromised",
				"If this server has already run against a machine with real " +
					"keys, rotate them rather than reasoning about whether " +
					"this particular path was taken."},
		},
		Note: "Seen over plain HTTP, on stderr, and on the pipe back to " +
			"passmcp. A tunnel is opaque on purpose: passmcp reads a CONNECT " +
			"destination and never the payload, because the alternative is " +
			"installing a certificate authority to decrypt traffic it was " +
			"not asked to decrypt. Over https the destination is reported by " +
			"`egress.hosts` and the payload is not.",
	},

	"egress.undeclared_host": {
		Means: "The server connected to a host that `--expect-egress` does " +
			"not name. passmcp saw it because it started the process and " +
			"pointed its proxy settings at a listener of its own, which is " +
			"the only way to see a destination that appears in no manifest, " +
			"no catalogue and no documentation — a destination nobody " +
			"declared is not declared on purpose.",
		Steps: []Step{
			{"Find out what the host is",
				"The finding names it and says how many times it was reached. " +
					"A CDN, a telemetry endpoint and an exfiltration target all " +
					"look the same from here; only somebody who knows the " +
					"server can tell them apart."},
			{"Add it if it is a dependency",
				"`--expect-egress api.example.com`, repeatable, and a leading " +
					"dot matches subdomains. An expectation that is written " +
					"down is one the next run enforces."},
			{"Treat an unexplained host as an incident",
				"A server that contacts somewhere its author cannot account " +
					"for, on a run where it was handed tool arguments, is the " +
					"case this check exists for. Check what it was given before " +
					"the connection."},
		},
		Note: "Watched only with `--watch-egress`, and only over stdio, " +
			"because it works by setting the child's environment. Two blind " +
			"spots worth knowing: a destination on the same machine is not " +
			"seen, since almost every runtime refuses to proxy loopback, and " +
			"a client that ignores the proxy environment entirely is not seen " +
			"either.",
	},

	"stdio.process": {
		Means: "The program passmcp was told to run exited before it answered a " +
			"single request. Nothing after this could be tested, so the rest of " +
			"the report is empty rather than clean — a host starting this server " +
			"would see the same thing and report that the server is unavailable.",
		Steps: []Step{
			{"Run the command yourself, exactly as passmcp did",
				"The report names it, including the arguments. A server that exits " +
					"immediately almost always says why on stderr, and the finding " +
					"carries whatever it said."},
			{"Check what it needed that it did not get",
				"The three usual causes are a missing argument, a working directory " +
					"it did not expect, and an environment variable it reads at " +
					"startup. passmcp passes a fixed base environment and nothing " +
					"else, so a server that needs a credential must be given it by " +
					"name with --stdio-env."},
			{"Make the failure legible",
				"Exit with a message on stderr that names what was missing. A host " +
					"has no other channel: it sees a process that died, and an " +
					"operator sees a client that will not connect."},
		},
	},

	"stdio.alive": {
		Means: "The server was running when the run started and had exited before " +
			"it finished. A host keeps one process for a whole session, so an exit " +
			"partway through does not end one request — it ends every conversation " +
			"that process was holding, and the user sees their assistant lose the " +
			"ability to use the server mid-task.",
		Steps: []Step{
			{"Find the last request it answered",
				"Run with --report-dir and read the telemetry: the last recorded " +
					"message is the one it died on or just after. What the server " +
					"wrote to stderr is in the finding's evidence."},
			{"Handle the failure instead of exiting",
				"An unhandled exception in a tool handler, an assertion, or a " +
					"deliberate exit on bad input all present identically to a host. " +
					"Return a JSON-RPC error, or an isError result, and stay up."},
			{"Do not exit on a message you did not understand",
				"An unknown method, a malformed body and an unexpected " +
					"notification are all things a client will legitimately send. " +
					"Answering with an error is correct; dying is not."},
		},
	},

	"stdio.stdout_clean": {
		Means: "The server wrote something to stdout that was not a JSON-RPC " +
			"message. Over stdio, stdout is the wire: every byte on it is parsed " +
			"as protocol framing. One banner, one print statement left in a " +
			"handler, or a progress bar is enough to corrupt the stream, and the " +
			"client cannot recover — it sees a parse error, or nothing at all.",
		Steps: []Step{
			{"Send every log line to stderr",
				"passmcp keeps stderr and reports it; nothing is lost by moving it " +
					"there. In most languages this is one change to the logger's " +
					"destination, and it is the whole fix."},
			{"Look for the ones that are not logging",
				"A framework's startup banner, a dependency that prints on import, " +
					"a deprecation warning from the runtime, a debugger left " +
					"attached. The finding quotes the first line it saw, which is " +
					"usually enough to identify the source."},
			{"Keep stdout for the transport, permanently",
				"Redirect the process's own stdout to stderr at startup, before " +
					"anything else runs, and write protocol messages through the " +
					"handle you saved. Then a stray print by anything you depend on " +
					"cannot break the transport."},
		},
		Note: "This is the single most common way a working server appears broken " +
			"to a host, because the symptom never names the cause.",
	},

	"stdio.post_init_connections": {
		Means: "After its handshake the server held a socket to a non-loopback " +
			"address that did not go through passmcp's proxy. After the handshake " +
			"every action is one a request caused, and a connection made around " +
			"HTTP_PROXY is invisible to egress.hosts, so this is the destination " +
			"passmcp could not name.",
		Steps: []Step{
			{"Reach the network through the configured proxy",
				"Use an HTTP client that honours HTTP_PROXY and HTTPS_PROXY, so " +
					"an operator can see and govern where the server goes."},
			{"Connect only for the call that needs it",
				"A read-only lookup that opens a socket to an address nobody " +
					"configured is the shape exfiltration takes, whatever the intent."},
		},
		Note: "Seen by sampling /proc on Linux; a connection opened and closed " +
			"between two samples is not seen, so no finding is not a guarantee.",
	},

	"stdio.post_init_writes": {
		Means: "After its handshake the server held a file open for writing " +
			"outside the working directory it was started in. A tool call should " +
			"not leave the server writing to the user's home or system paths.",
		Steps: []Step{
			{"Write under the working directory, or a configured path",
				"Put caches and state where the host told the server to run, or " +
					"where the operator named in configuration."},
		},
		Note: "Seen by sampling /proc on Linux; passmcp's scratch home and /dev, " +
			"/proc and /sys are not reported.",
	},
}
