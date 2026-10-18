CREATE OR REPLACE VIEW host AS
  SELECT *
  FROM read_parquet(
    '/dados/lucca/tcc-nids-hids/data/processed/ecs/host/*.parquet',
    union_by_name = true
  );

SELECT count(*) AS eventos FROM host;