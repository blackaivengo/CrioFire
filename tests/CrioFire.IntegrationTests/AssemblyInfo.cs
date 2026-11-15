// All tests here change the same machine-wide firewall state, so they must never run in parallel.
[assembly: Xunit.v3.Parallelization(Mode = Xunit.Sdk.ParallelMode.None)]
