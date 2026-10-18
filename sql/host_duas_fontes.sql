SELECT
    "host.name" AS host,
    "source.ip" AS ip,
    "event.dataset" AS fonte,
    count(*) AS falhas,
    min("@timestamp") AS primeira,
    max("@timestamp") AS ultima
FROM host
WHERE "labels.dataset" = 'camlds'
  AND "labels.scenario" = 'scenario_3_ssh_puppet'
  AND "host.name" = 'puppet'
  AND "source.ip" = '192.42.1.174'
  AND "event.outcome" = 'failure'
  AND (
      (
          "event.dataset" = 'system.auth'
          AND "event.action" = 'ssh_login'
      )
      OR
      (
          "event.dataset" = 'auditd.log'
          AND "event.action" = 'auditd_user_auth'
      )
  )
GROUP BY ALL
ORDER BY fonte;