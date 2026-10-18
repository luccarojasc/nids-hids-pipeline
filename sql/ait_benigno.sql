-- Russellmitchell: UTC adotado como interpretação operacional.
-- A seleção final da amostra benigna permanece em validação.

WITH periodos(cenario, inicio, fim) AS (
    VALUES (
        'russellmitchell',
        TIMESTAMPTZ '2022-01-21 00:00:00+00',
        TIMESTAMPTZ '2022-01-25 00:00:00+00'
    )
)
SELECT
    h."labels.scenario" AS cenario,
    h."host.name" AS host,
    date_trunc('day', h."@timestamp") AS dia,
    count(*) FILTER (
        WHERE h."event.outcome" = 'failure'
          AND h."labels.attack" = ''
    ) AS falhas_sem_rotulo,
    count(*) FILTER (
        WHERE h."event.outcome" = 'success'
          AND h."labels.attack" = ''
    ) AS sucessos_sem_rotulo,
    count(*) FILTER (
        WHERE h."labels.attack" <> ''
    ) AS autenticacoes_rotuladas,
    count(*) FILTER (
        WHERE h."labels.attack" IS NULL
    ) AS rotulo_nulo
FROM host h
JOIN periodos p ON h."labels.scenario" = p.cenario
WHERE h."labels.dataset" = 'ait'
  AND h."event.dataset" = 'system.auth'
  AND h."event.action" = 'ssh_login'
  AND h."@timestamp" >= p.inicio
  AND h."@timestamp" < p.fim
GROUP BY ALL
ORDER BY cenario, host, dia;