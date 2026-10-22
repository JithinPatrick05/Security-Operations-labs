# Investigation Notes

## Pivots

I did not start with a general search. The earlier labs had already given me:

- Host: JPtest1
- Process ID: 6124
- Process: powershell.exe
- DNS name: cdn-storage-sync.test
- Destination: 203.0.113.77:443
- First network event: 2026-10-22 16:46:04.118 UTC

Those became the Sentinel pivots.

## Query order

I worked through the data in this order:

1. Event ID 1 to confirm the process.
2. Event ID 22 to tie that process to DNS.
3. Event ID 3 to confirm the outbound connections.
4. A summary query to reduce the six network events into one result.

## Time correlation

The events line up as follows:

~~~text
16:46:02.811  PowerShell created
16:46:03.447  DNS query
16:46:04.118  First network connection
~~~

Process to DNS: 636 ms

DNS to first connection: 671 ms

The next five connections remained approximately one minute apart.

## Outcome

The Sentinel results did not add a new endpoint behaviour that was missing from the previous lab. What they added was a central place to query the activity and a repeatable set of KQL pivots that could be expanded across more hosts.

That is the main reason I would use the same approach in a SOC environment: start with a known indicator, identify the responsible process, then widen the search once the local chain makes sense.
