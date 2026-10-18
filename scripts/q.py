import sys
from pathlib import Path

import duckdb

DB = Path("/dados/lucca/tcc-nids-hids/data/processed/eventos.duckdb")

src = sys.argv[1]
sql = Path(src).read_text() if src.endswith(".sql") else src
con = duckdb.connect(str(DB))
# Exibir timestamps em UTC, independentemente do fuso da sessão.
con.execute("SET TimeZone = 'UTC'")
rel = con.sql(sql)
if rel is not None:
    rel.show(max_rows=60, max_width=220)