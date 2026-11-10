// All tests here change the same machine-wide firewall state, so they must never run in parallel.
[assembly: CollectionBehavior(DisableTestParallelization = true)]
