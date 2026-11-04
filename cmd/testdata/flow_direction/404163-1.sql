-- direction-generator: cumulative-v1
-- Rendering: grouped scalar rules; cumulative evidence and policies are unchanged.
CREATE OR REPLACE MATERIALIZED VIEW
  `{{gcp_project_id}}.{{bq_dataset}}.mv-flow-data-404163-1`
PARTITION BY TIMESTAMP_TRUNC(start_time, HOUR)
AS
WITH parsed AS (
  SELECT
    device_id,
    start_time,
    end_time,
    src_ip,
    dst_ip,
    src_port,
    dst_port,
    bytes_to_srv,
    bytes_to_client,
    pckt_to_srv,
    pckt_to_client,
    LOWER(protocol) AS protocol_lc,
    NET.SAFE_IP_FROM_STRING(src_ip) AS src_ip_bytes,
    NET.SAFE_IP_FROM_STRING(dst_ip) AS dst_ip_bytes
  FROM `{{gcp_project_id}}.{{bq_dataset}}.flow-data-404163-1`
),
base AS (
  SELECT
    device_id,
    start_time,
    end_time,
    src_ip,
    dst_ip,
    src_port,
    dst_port,
    bytes_to_srv,
    bytes_to_client,
    pckt_to_srv,
    pckt_to_client,
    protocol_lc,
    COALESCE(
      (
        NET.IP_TRUNC(src_ip_bytes, 8) = NET.IP_FROM_STRING('10.0.0.0')
        OR NET.IP_TRUNC(src_ip_bytes, 12) = NET.IP_FROM_STRING('172.16.0.0')
        OR NET.IP_TRUNC(src_ip_bytes, 16) = NET.IP_FROM_STRING('192.168.0.0')
        OR NET.IP_TRUNC(src_ip_bytes, 10) = NET.IP_FROM_STRING('100.64.0.0')
      ),
      FALSE
    ) AS src_is_private,
    COALESCE(
      (
        NET.IP_TRUNC(dst_ip_bytes, 8) = NET.IP_FROM_STRING('10.0.0.0')
        OR NET.IP_TRUNC(dst_ip_bytes, 12) = NET.IP_FROM_STRING('172.16.0.0')
        OR NET.IP_TRUNC(dst_ip_bytes, 16) = NET.IP_FROM_STRING('192.168.0.0')
        OR NET.IP_TRUNC(dst_ip_bytes, 10) = NET.IP_FROM_STRING('100.64.0.0')
      ),
      FALSE
    ) AS dst_is_private
  FROM parsed
),
learned AS (
  SELECT
    device_id,
    start_time,
    end_time,
    src_ip,
    dst_ip,
    src_port,
    dst_port,
    bytes_to_srv,
    bytes_to_client,
    pckt_to_srv,
    pckt_to_client,
    protocol_lc,
    src_is_private,
    dst_is_private,
    -- Mirroring exchanges both selectors; NULL matches remain NULL.
    -- tcp endpoint evidence.
    (
      (
        src_ip = '10.241.220.160'
        AND src_port IN (80, 443, 9999)
      )
      OR (
        src_ip = '10.241.220.227'
        AND src_port IN (80, 443, 9999)
      )
      OR (
        src_ip = '10.241.221.116'
        AND src_port IN (9999)
      )
      OR (
        src_ip = '10.241.221.122'
        AND src_port IN (9999)
      )
      OR (
        src_ip = '10.241.221.124'
        AND src_port IN (53, 853)
      )
      OR (
        src_ip = '10.241.221.126'
        AND src_port IN (80, 443, 9999)
      )
      OR (
        src_ip = '10.241.221.20'
        AND src_port IN (9999)
      )
      OR (
        src_ip = '10.241.221.39'
        AND src_port IN (9999)
      )
      OR (
        src_ip = '10.241.221.41'
        AND src_port IN (80, 443, 9999)
      )
      OR (
        src_ip = '10.241.221.47'
        AND src_port IN (9999)
      )
      OR (
        src_ip = '10.241.221.55'
        AND src_port IN (9999)
      )
      OR (
        src_ip = '10.241.221.59'
        AND src_port IN (21000)
      )
      OR (
        src_ip = '10.241.221.62'
        AND src_port IN (53, 853)
      )
      OR (
        src_ip = '10.241.221.8'
        AND src_port IN (9999)
      )
      OR (
        src_ip = '10.241.221.84'
        AND src_port IN (9999)
      )
      OR (
        src_ip = '10.241.221.98'
        AND src_port IN (9999)
      )
      OR (
        src_ip = '10.4.0.230'
        AND src_port IN (53)
      )
      OR (
        src_ip = '10.4.0.240'
        AND src_port IN (53)
      )
      OR (
        dst_ip = '10.127.168.154'
        AND src_port IN (7680)
      )
      OR (
        dst_ip = '10.241.155.157'
        AND src_port IN (443, 8880, 9001)
      )
      OR (
        dst_ip = '10.241.220.164'
        AND src_port IN (8880)
      )
      OR (
        dst_ip = '10.241.220.181'
        AND src_port IN (8880)
      )
      OR (
        dst_ip = '10.241.220.226'
        AND src_port IN (8880)
      )
      OR (
        dst_ip = '10.241.220.232'
        AND src_port IN (8880)
      )
      OR (
        dst_ip = '10.241.221.10'
        AND src_port IN (8080, 8085, 8888, 18083)
      )
      OR (
        dst_ip = '10.241.221.101'
        AND src_port IN (8443, 8880)
      )
      OR (
        dst_ip = '10.241.221.105'
        AND src_port IN (8080, 8085, 8888, 18083)
      )
      OR (
        dst_ip = '10.241.221.114'
        AND src_port IN (8080, 8888)
      )
      OR (
        dst_ip = '10.241.221.213'
        AND src_port IN (8085)
      )
      OR (
        dst_ip = '10.241.221.217'
        AND src_port IN (8085, 8888)
      )
      OR (
        dst_ip = '10.241.221.32'
        AND src_port IN (8080, 8085, 8888, 18083)
      )
      OR (
        dst_ip = '10.241.221.33'
        AND src_port IN (8080, 8888, 18083)
      )
      OR (
        dst_ip = '10.241.221.4'
        AND src_port IN (8080, 8888, 18083)
      )
      OR (
        dst_ip = '10.241.221.82'
        AND src_port IN (8443, 8880)
      )
      OR (
        dst_ip = '10.241.221.91'
        AND src_port IN (8080, 8888)
      )
      OR (
        dst_ip = '10.241.221.96'
        AND src_port IN (8080, 8085, 8888, 18083)
      )
      OR (
        dst_ip = '10.76.113.140'
        AND src_port IN (7680)
      )
      OR (
        dst_ip = '10.76.198.43'
        AND src_port IN (7680)
      )
    ) AS learned_reverse_match,
    (
      (
        dst_ip = '10.241.220.160'
        AND dst_port IN (80, 443, 9999)
      )
      OR (
        dst_ip = '10.241.220.227'
        AND dst_port IN (80, 443, 9999)
      )
      OR (
        dst_ip = '10.241.221.116'
        AND dst_port IN (9999)
      )
      OR (
        dst_ip = '10.241.221.122'
        AND dst_port IN (9999)
      )
      OR (
        dst_ip = '10.241.221.124'
        AND dst_port IN (53, 853)
      )
      OR (
        dst_ip = '10.241.221.126'
        AND dst_port IN (80, 443, 9999)
      )
      OR (
        dst_ip = '10.241.221.20'
        AND dst_port IN (9999)
      )
      OR (
        dst_ip = '10.241.221.39'
        AND dst_port IN (9999)
      )
      OR (
        dst_ip = '10.241.221.41'
        AND dst_port IN (80, 443, 9999)
      )
      OR (
        dst_ip = '10.241.221.47'
        AND dst_port IN (9999)
      )
      OR (
        dst_ip = '10.241.221.55'
        AND dst_port IN (9999)
      )
      OR (
        dst_ip = '10.241.221.59'
        AND dst_port IN (21000)
      )
      OR (
        dst_ip = '10.241.221.62'
        AND dst_port IN (53, 853)
      )
      OR (
        dst_ip = '10.241.221.8'
        AND dst_port IN (9999)
      )
      OR (
        dst_ip = '10.241.221.84'
        AND dst_port IN (9999)
      )
      OR (
        dst_ip = '10.241.221.98'
        AND dst_port IN (9999)
      )
      OR (
        dst_ip = '10.4.0.230'
        AND dst_port IN (53)
      )
      OR (
        dst_ip = '10.4.0.240'
        AND dst_port IN (53)
      )
      OR (
        src_ip = '10.127.168.154'
        AND dst_port IN (7680)
      )
      OR (
        src_ip = '10.241.155.157'
        AND dst_port IN (443, 8880, 9001)
      )
      OR (
        src_ip = '10.241.220.164'
        AND dst_port IN (8880)
      )
      OR (
        src_ip = '10.241.220.181'
        AND dst_port IN (8880)
      )
      OR (
        src_ip = '10.241.220.226'
        AND dst_port IN (8880)
      )
      OR (
        src_ip = '10.241.220.232'
        AND dst_port IN (8880)
      )
      OR (
        src_ip = '10.241.221.10'
        AND dst_port IN (8080, 8085, 8888, 18083)
      )
      OR (
        src_ip = '10.241.221.101'
        AND dst_port IN (8443, 8880)
      )
      OR (
        src_ip = '10.241.221.105'
        AND dst_port IN (8080, 8085, 8888, 18083)
      )
      OR (
        src_ip = '10.241.221.114'
        AND dst_port IN (8080, 8888)
      )
      OR (
        src_ip = '10.241.221.213'
        AND dst_port IN (8085)
      )
      OR (
        src_ip = '10.241.221.217'
        AND dst_port IN (8085, 8888)
      )
      OR (
        src_ip = '10.241.221.32'
        AND dst_port IN (8080, 8085, 8888, 18083)
      )
      OR (
        src_ip = '10.241.221.33'
        AND dst_port IN (8080, 8888, 18083)
      )
      OR (
        src_ip = '10.241.221.4'
        AND dst_port IN (8080, 8888, 18083)
      )
      OR (
        src_ip = '10.241.221.82'
        AND dst_port IN (8443, 8880)
      )
      OR (
        src_ip = '10.241.221.91'
        AND dst_port IN (8080, 8888)
      )
      OR (
        src_ip = '10.241.221.96'
        AND dst_port IN (8080, 8085, 8888, 18083)
      )
      OR (
        src_ip = '10.76.113.140'
        AND dst_port IN (7680)
      )
      OR (
        src_ip = '10.76.198.43'
        AND dst_port IN (7680)
      )
    ) AS learned_forward_match
  FROM base
),
decide AS (
  SELECT
    device_id,
    start_time,
    end_time,
    src_ip,
    dst_ip,
    src_port,
    dst_port,
    bytes_to_srv,
    bytes_to_client,
    pckt_to_srv,
    pckt_to_client,
    protocol_lc,
    CASE
      -- Priority: outside-to-private, DNS, then unambiguous learned direction.
      WHEN NOT src_is_private
        AND dst_is_private
        THEN 'public_to_private_artifact'
      WHEN src_is_private AND dst_is_private
        AND protocol_lc = 'udp'
        AND src_port = 53
        AND dst_port != 53
        THEN 'udp_dns_response'
      -- A forward match suppresses reversal, including conflicting endpoint roles.
      WHEN src_is_private AND dst_is_private
        AND protocol_lc = 'tcp'
        AND learned_reverse_match
        AND NOT learned_forward_match
        THEN 'learned_endpoint_reversed'
      ELSE NULL
    END AS swap_reason
  FROM learned
)
SELECT
  device_id,
  start_time,
  end_time,
  IF(swap_reason IS NOT NULL, dst_ip, src_ip) AS src_ip,
  IF(swap_reason IS NOT NULL, src_ip, dst_ip) AS dst_ip,
  IF(swap_reason IS NOT NULL, dst_port, src_port) AS src_port,
  IF(swap_reason IS NOT NULL, src_port, dst_port) AS dst_port,
  protocol_lc AS protocol,
  IF(swap_reason IS NOT NULL, bytes_to_client, bytes_to_srv) AS bytes_to_srv,
  IF(swap_reason IS NOT NULL, bytes_to_srv, bytes_to_client) AS bytes_to_client,
  IF(swap_reason IS NOT NULL, pckt_to_client, pckt_to_srv) AS pckt_to_srv,
  IF(swap_reason IS NOT NULL, pckt_to_srv, pckt_to_client) AS pckt_to_client
FROM decide;
