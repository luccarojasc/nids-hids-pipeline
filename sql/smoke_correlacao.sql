WITH h AS (
  SELECT "source.ip" AS ip, count(*) AS falhas_host,
         min("@timestamp") AS host_inicio, max("@timestamp") AS host_fim
  FROM host
  WHERE "labels.scenario" = 'scenario_3_ssh_puppet'
    AND "event.dataset" = 'system.auth' AND "event.action" = 'ssh_login'
    AND "event.outcome" = 'failure'
  GROUP BY 1
), r AS (
  SELECT "source.ip" AS ip, count(*) AS conexoes,
         min("@timestamp") AS rede_inicio, max("@timestamp") AS rede_fim,
         round(median("event.duration") / 1e9, 2) AS duracao_mediana_s
  FROM rede
  WHERE "labels.scenario" = 'scenario_3_ssh_puppet' AND "destination.port" = 22
  GROUP BY 1
)
SELECT * FROM h FULL JOIN r USING (ip)
ORDER BY falhas_host DESC NULLS LAST
LIMIT 10;