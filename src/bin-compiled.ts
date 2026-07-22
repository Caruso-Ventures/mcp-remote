import { runFromArgv } from './bin'

// COMPILED-ARGV-SLICE: argv probe (Verify-A step 1) showed `bun build --compile`
// yields argv = [execPath, scriptPath, ...userArgs] (length 4 for 2 user args),
// same shape as a plain node invocation — so slice(2), not slice(1). Probe-confirmed.
runFromArgv(process.argv.slice(2))
