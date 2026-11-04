-- direction-generator: cumulative-v1
-- Rendering: grouped scalar rules; cumulative evidence and policies are unchanged.
CREATE OR REPLACE MATERIALIZED VIEW
  `{{gcp_project_id}}.{{bq_dataset}}.mv-flow-data-mixed`
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
  FROM `{{gcp_project_id}}.{{bq_dataset}}.flow-data-mixed`
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
        src_ip = '10.4.100.58'
        AND src_port IN (80, 443, 1883)
      )
      OR (
        src_ip = '10.4.100.59'
        AND src_port IN (443)
      )
      OR (
        src_ip = '100.65.1.1'
        AND src_port IN (
          1000, 1001, 1002, 1003, 1004, 1005, 1006, 1007, 1008, 1009, 1010, 1011, 1012, 1013, 1014,
          1015, 1016, 1017, 1018, 1019, 1020, 1021, 1022, 1023, 1024, 1025, 1026, 1027, 1028, 1029,
          1030, 1031, 1032, 1033, 1034, 1035, 1036, 1037, 1038, 1039
        )
      )
      OR (
        dst_ip = '10.4.100.58'
        AND src_port IN (22)
      )
      OR (
        dst_ip = '10.4.100.59'
        AND src_port IN (80)
      )
    ) AS learned_reverse_match,
    (
      (
        dst_ip = '10.4.100.58'
        AND dst_port IN (80, 443, 1883)
      )
      OR (
        dst_ip = '10.4.100.59'
        AND dst_port IN (443)
      )
      OR (
        dst_ip = '100.65.1.1'
        AND dst_port IN (
          1000, 1001, 1002, 1003, 1004, 1005, 1006, 1007, 1008, 1009, 1010, 1011, 1012, 1013, 1014,
          1015, 1016, 1017, 1018, 1019, 1020, 1021, 1022, 1023, 1024, 1025, 1026, 1027, 1028, 1029,
          1030, 1031, 1032, 1033, 1034, 1035, 1036, 1037, 1038, 1039
        )
      )
      OR (
        src_ip = '10.4.100.58'
        AND dst_port IN (22)
      )
      OR (
        src_ip = '10.4.100.59'
        AND dst_port IN (80)
      )
    ) AS learned_forward_match,
    -- udp endpoint evidence.
    (
      (
        src_ip = '10.4.100.58'
        AND src_port IN (53, 6514)
      )
      OR (
        src_ip = '10.4.100.59'
        AND src_port IN (6514)
      )
    ) AS learned_reverse_match_udp,
    (
      (
        dst_ip = '10.4.100.58'
        AND dst_port IN (53, 6514)
      )
      OR (
        dst_ip = '10.4.100.59'
        AND dst_port IN (6514)
      )
    ) AS learned_forward_match_udp
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
      -- DNS preservation must precede learned syslog UDP correction.
      WHEN src_is_private AND dst_is_private
        AND protocol_lc = 'udp'
        AND (src_port = 53 OR dst_port = 53)
        THEN NULL
      -- A forward match suppresses reversal, including conflicting endpoint roles.
      WHEN src_is_private AND dst_is_private
        AND protocol_lc = 'tcp'
        AND learned_reverse_match
        AND NOT learned_forward_match
        THEN 'learned_endpoint_reversed'
      -- A forward match suppresses reversal, including conflicting endpoint roles.
      WHEN src_is_private AND dst_is_private
        AND protocol_lc = 'udp'
        AND learned_reverse_match_udp
        AND NOT learned_forward_match_udp
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
