CREATE OR REPLACE VIEW host AS
SELECT *
FROM read_parquet(
  '/dados/lucca/tcc-nids-hids/data/processed/ecs/host/*.parquet',
  union_by_name = true
);

CREATE OR REPLACE VIEW rede AS
SELECT *
FROM read_parquet(
  '/dados/lucca/tcc-nids-hids/data/processed/ecs/rede/*.parquet',
  union_by_name = true
);

CREATE OR REPLACE VIEW eventos AS
SELECT * FROM host
UNION ALL BY NAME
SELECT * FROM rede;

SELECT
  "event.category" AS plano,
  "event.dataset" AS fonte,
  "labels.dataset" AS base,
  count(*) AS n
FROM eventos
GROUP BY ALL
ORDER BY ALL;