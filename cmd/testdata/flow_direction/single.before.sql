-- direction-generator: cumulative-v1
CREATE OR REPLACE MATERIALIZED VIEW `{{gcp_project_id}}.{{bq_dataset}}.mv-flow-data-single`
PARTITION BY TIMESTAMP_TRUNC(start_time, HOUR)
AS
WITH base AS (
  SELECT
    device_id, start_time, end_time,
    src_ip, dst_ip, src_port, dst_port,
    bytes_to_srv, bytes_to_client,
    pckt_to_srv, pckt_to_client,
    LOWER(protocol) AS protocol_lc,
    COALESCE(
      (
        NET.IP_TRUNC(NET.SAFE_IP_FROM_STRING(src_ip), 8) = NET.IP_FROM_STRING('10.0.0.0')
        OR NET.IP_TRUNC(NET.SAFE_IP_FROM_STRING(src_ip), 12) = NET.IP_FROM_STRING('172.16.0.0')
        OR NET.IP_TRUNC(NET.SAFE_IP_FROM_STRING(src_ip), 16) = NET.IP_FROM_STRING('192.168.0.0')
        OR NET.IP_TRUNC(NET.SAFE_IP_FROM_STRING(src_ip), 10) = NET.IP_FROM_STRING('100.64.0.0')
      ),
      FALSE
    ) AS src_is_private,
    COALESCE(
      (
        NET.IP_TRUNC(NET.SAFE_IP_FROM_STRING(dst_ip), 8) = NET.IP_FROM_STRING('10.0.0.0')
        OR NET.IP_TRUNC(NET.SAFE_IP_FROM_STRING(dst_ip), 12) = NET.IP_FROM_STRING('172.16.0.0')
        OR NET.IP_TRUNC(NET.SAFE_IP_FROM_STRING(dst_ip), 16) = NET.IP_FROM_STRING('192.168.0.0')
        OR NET.IP_TRUNC(NET.SAFE_IP_FROM_STRING(dst_ip), 10) = NET.IP_FROM_STRING('100.64.0.0')
      ),
      FALSE
    ) AS dst_is_private
  FROM `{{gcp_project_id}}.{{bq_dataset}}.flow-data-single`
),
decide AS (
  SELECT
    *,
    CASE
      WHEN (NOT src_is_private) AND dst_is_private
        THEN 'public_to_private_artifact'
      WHEN src_is_private AND dst_is_private AND protocol_lc = 'udp' AND src_port = 53 AND dst_port != 53 THEN 'udp_dns_response'
      WHEN src_is_private AND dst_is_private AND protocol_lc = 'udp' AND (src_port = 53 OR dst_port = 53) THEN NULL
      WHEN src_is_private AND dst_is_private AND ((protocol_lc = 'tcp' AND src_ip = '10.4.100.58' AND src_port = 80)) AND NOT ((protocol_lc = 'tcp' AND dst_ip = '10.4.100.58' AND dst_port = 80)) THEN 'learned_endpoint_reversed'
      ELSE NULL
    END AS swap_reason
  FROM base
)
SELECT
  device_id, start_time, end_time,
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
