check_naglio_aeropsike
======================

Nagios plugins that parse output from aerospike tools. Plugins check threshold, and produce a lot of performance data.



check_naglio_aeropsike_statistics.pl
--------------

Plugin parses output of "asinfo -v statistics", example parameters for check  two node cluster:

<pre>
./check_naglio_aeropsike_statistics.pl -A \
        -o  'NAME:cluster_integrity,CRIT:!1' \
        -o  'NAME:client_connections,WARN:>1000,CRIT:>10000' \
        -o  'NAME:cluster_size,WARN:2:2,CRIT:0:3' \
        -o  'NAME:err_out_of_space,CRIT:>0' \
        -o  'NAME:migrate_progress_recv,WARN:>0' \
        -o  'NAME:migrate_progress_send,WARN:>0' \
        -o  'NAME:uptime,WARN:<300' \
        -o  'NAME:free-pct-disk,WARN:<60,CRIT:<52' \
        -o  'NAME:free-pct-memory,WARN:<50,CRIT:<42' \
        -o  'NAME:partition_desync,WARN:>1,CRIT:>10' \
        -o  'NAME:reaped_fds_rate_ps,WARN:>1,CRIT:>10' \
        -o  'PATTERN:err_rw_request_not_found_rate_ps,WARN:>1,CRIT:>10' \
        -o  'PATTERN:stat_read_errs_notfound_rate_ps,WARN:>100000,CRIT:>200000' \
        -o  'PATTERN:.*err.*_rate_ps,WARN:>0,CRIT:>100'
</pre>


check_naglio_aeropsike_namespace.pl
--------------

Plugin parses output of "asinfo -v namespace/<namespacename>", example for namespace "test":

<pre>
./check_naglio_aeropsike_namespace.pl -A -n test \
        -o 'NAME:hwm-breached,CRIT:!0' \
        -o 'NAME:stop-writes,CRIT:!0' \
        -o 'NAME:available-bin-names,WARN:<10000,CRIT:<1000' \
        -o 'NAME:available_pct,WARN:<30,CRIT:<15' \
        -o 'NAME:evicted-objects_rate_ps,CRIT:>1' \
        -o 'NAME:free-pct-disk,WARN:<60,CRIT:<52' \
        -o 'NAME:free-pct-memory,WARN:<50,CRIT:<42'
</pre>


check_naglio_aeropsike_latency.pl
--------------

Plugin is intended to run once at 60 seconds and parses output of "asloglatency -h $histogram  -f -60 -e 1 -n 6", where $histogram=('reads','writes_master','proxy','writes_reply','udf','query','query_rec_count'):


<pre>
./check_naglio_aeropsike_latency.pl -A \
       -o  'PATTERN:.*_ms1,WARN:>1,CRIT:>10'
</pre>


