SELECT
    "labels.scenario" AS cenario,
    "host.name" AS host,
    "source.ip" AS ip,
    "user.name" AS usuario,
    count(*) FILTER (
        WHERE "event.outcome" = 'failure'
    ) AS falhas,
    count(*) FILTER (
        WHERE "event.outcome" = 'success'
    ) AS sucessos,
    min("@timestamp") AS primeiro,
    max("@timestamp") AS ultimo
FROM host
WHERE "event.dataset" = 'system.auth'
  AND "event.action" = 'ssh_login'
GROUP BY ALL
ORDER BY cenario, host, ip, usuario;