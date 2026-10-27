# CP5 — Análise descritiva e sensibilidade da janela temporal

## 1. Objetivo e estado

Consolidar os resultados observados nas configurações B1, B2 e B3 e examinar sua sensibilidade à janela temporal, preservando os dados, as regras e os demais parâmetros do motor.

A campanha da Semana 8 foi executada e verificada com sucesso. A análise abrange janelas de 60, 300 e 600 segundos, mantendo 300 segundos como configuração principal.

Estado: verificações técnicas concluídas; relatório preparado para revisão. O fechamento documental e o versionamento final da Semana 8 serão registrados após sua conclusão. Este documento não constitui aprovação do orientador.

As métricas de eficácia permanecem desabilitadas. A campanha não acrescenta amostras experimentais independentes.

## 2. Proveniência e ambiente

### 2.1. Campanha

- Diretório: `out/semana8/campanha-20261027T004827Z`.
- Contrato: `semana8_sensibilidade_v1`.
- Commit da execução: `0a5011d57083f0fc6e1731465e28b748888520a7`.
- Referência principal: `out/semana7/campanha-20261026T011425Z/all`.
- Referência de ingestão e contadores: `out/semana4/execucao-20261018T163915Z`.
- Configuração original do detector: `config/motor-semana5.json`.

O identificador da campanha registra 27/10/2026 às 00:48:27 UTC, correspondente a 26/10/2026 às 21:48:27 no fuso de São Paulo.

### 2.2. Integridade

| Artefato | SHA-256 |
|---|---|
| Manifesto da campanha da Semana 8 | `76ad434926f6de880ea03e605ae007a52586d720a45b25801782f613a8663654` |
| Configuração original da Semana 5 | `589d1d6ceb59fd92da10cff985e071ae2ac435ec8dba46f58de411009492ada1` |
| Manifesto da referência da Semana 7 | `47a772b2a4c5ca4c1107ec757cbf1bd4ee95bf077c30988c3aa04f6c1095a1a1` |
| Manifesto da referência da Semana 4 | `961c97ab2ccc5ce7fb69cd7e44d19d5f2cba942fc5628543fe7f33c32e480ffb` |

O hash da configuração original foi conferido novamente após a campanha e coincide com a referência registrada.

Os hashes dos códigos, regras, protocolo e saídas estão em `manifest.json`.

### 2.3. Ambiente e testes

- Python: `3.10.12`.
- pandas: `2.3.3`.
- PyYAML: `6.0.3`.
- Testes específicos da Semana 8: **8 aprovados**.
- Suíte completa: **98 aprovados**.
- Compilação, interface, execução e verificação da campanha: status **0**.

Os testes validam propriedades do software. Não representam novas observações de ataques ou atividade benigna.

## 3. Desenho da análise de sensibilidade

### 3.1. Parâmetro variado

Apenas a janela dos contadores foi alterada, em cópias das configurações:

| Variante | Janela |
|---|---:|
| `w060` | 60 s |
| `w300` | 300 s — principal |
| `w600` | 600 s |

A configuração histórica foi preservada.

### 3.2. Parâmetros mantidos

| Parâmetro | Valor |
|---|---:|
| Limiar de host, Nh | 5 |
| Limiar de rede, Nn | 10 |
| Duração curta | Maior que zero e menor ou igual a 5 s |
| Horizonte de criticidade | 300 s |
| Idade máxima de associação | 300 s |
| Score base / crítico | 50 / 100 |
| TTL recomendado base / crítico | 900 / 1.800 s |

Foram mantidos os eventos, as seleções-base, o mapeamento de alvos e sensores, as regras de associação e a convenção de episódios.

O horizonte de criticidade e a idade máxima de associação permaneceram em 300 segundos, inclusive nas variantes de 60 e 600 segundos.

### 3.3. Executor e referência de equivalência

A campanha utiliza `scripts/semana8_sensibilidade.py`, que reaproveita a construção dos resultados pelo motor e verifica a variação exclusiva da janela.

Os validadores históricos foram preservados. A autorização das variantes é descrita pelo contrato externo da Semana 8.

A variante de 300 segundos foi comparada integralmente à referência da Semana 7, incluindo alertas, transições, decisões, verificações de criticidade, rastros, comparação e resumo. A equivalência foi confirmada.

As variantes devem ser verificadas pelo executor da Semana 8:

```bash
PYTHONPATH="$TCC/src" "$TCC/.venv/bin/python" \
  "$TCC/scripts/semana8_sensibilidade.py" verify \
  --root "$TCC" --out "$S8_OUT"
```

## 4. Qualidade e composição dos dados

### 4.1. Seleção

| Categoria | Registros |
|---|---:|
| Entradas | 219 |
| Eventos selecionados | 57 |
| Autenticação selecionada | 26 |
| Rede selecionada | 31 |
| Ação de host fora do contador | 8 |
| Fora do mapa de alvos e sensores | 5 |
| Auditoria usada somente para corroboração | 114 |
| Fora do período pelo início | 35 |
| Duplicatas identificadas pelo contrato | 0 |

Os motivos de exclusão totalizam 162 registros. Somados aos 57 selecionados, reconciliam as 219 entradas.

A auditoria não é somada novamente ao contador de falhas Nh.

### 4.2. Associação e duração

| Verificação | Resultado |
|---|---:|
| Mensagens de autenticação com candidato único no instante | 24 de 26 |
| Mensagens de autenticação sem candidato | 2 de 26 |
| Conexões com usuário associado único | 23 de 31 |
| Conexões sem usuário associado | 8 de 31 |
| Conexões selecionadas com duração ausente | 2 de 31 |

Os denominadores de autenticação e rede são distintos. As contagens não representam a mesma unidade de observação.

Ausência de associação não significa atividade benigna. Duração ausente não foi substituída por zero nem utilizada como evidência de conexão curta.

O arquivo `qualidade.json` incorpora o resumo da referência da Semana 4 e acrescenta informações sobre as conexões selecionadas. Seus campos `maxima` e `phase` pertencem à referência; não constituem máximos recalculados para cada janela da Semana 8.

## 5. Resultados por unidade de análise

A tabela resume os resultados observados em cada uma das três janelas.

| Unidade | Janela | B1: alertas | B2: alertas | B3: alertas |
|---|---:|---:|---:|---:|
| CAM puppet | 60 s | 1 | 2 | 0 |
| CAM puppet | 300 s | 1 | 2 | 0 |
| CAM puppet | 600 s | 1 | 2 | 0 |
| AIT intranet-server | 60 s | 0 | 0 | 0 |
| AIT intranet-server | 300 s | 0 | 0 | 0 |
| AIT intranet-server | 600 s | 0 | 0 | 0 |
| AIT mail | 60 s | 0 | 0 | 0 |
| AIT mail | 300 s | 0 | 0 | 0 |
| AIT mail | 600 s | 0 | 0 | 0 |

O arquivo `comparacao.csv` contém 27 linhas: três janelas, três unidades e três modos.

No CAM:

- B1 abriu um episódio para a origem `192.42.1.174`, sem atribuição de usuário.
- B2 abriu dois episódios, associados a `admin` e `root`.
- B3 não abriu episódios.
- Nenhum episódio foi promovido a crítico.

Nos recortes AIT, nenhum modo abriu alertas. Esses recortes continuam classificados como exploratórios, sem classe benigna confirmada para cálculo de falsos positivos.

A comparação é descritiva: B1 agrega por origem e alvo, enquanto B2 distingue usuários. Um episódio B1 e dois episódios B2 não demonstram, por si só, diferença de eficácia.

## 6. Instantes de abertura e contadores

Os instantes de abertura e os contadores de disparo permaneceram iguais nas três janelas.

Horários em UTC, em 12/12/2025:

| Modo | Usuário | Abertura | Nh no disparo | Nn no disparo |
|---|---|---|---:|---:|
| B1 | Não aplicável | 12:42:36.403263 | Não aplicável | 10 |
| B2 | admin | 12:42:37 | 7 | Não aplicável |
| B2 | root | 12:42:39 | 5 | Não aplicável |

Todos apresentaram score 50 e `critical=false`.

Os contadores registrados correspondem ao estado no instante de abertura. Eles não devem ser substituídos automaticamente pelo valor mínimo do limiar.

## 7. Encerramento e duração dos episódios

A variação da janela alterou os encerramentos dos episódios.

Horários em UTC, em 12/12/2025:

| Janela | Modo / usuário | Encerramento | Duração do episódio |
|---|---|---|---:|
| 60 s | B1 | 12:43:34.359848 | 57.956585 s |
| 60 s | B2 / admin | 12:43:36 | 59 s |
| 60 s | B2 / root | 12:43:36 | 57 s |
| 300 s | B1 | 12:47:34.359848 | 297.956585 s |
| 300 s | B2 / admin | 12:47:36 | 299 s |
| 300 s | B2 / root | 12:47:36 | 297 s |
| 600 s | B1 | 12:52:34.359848 | 597.956585 s |
| 600 s | B2 / admin | 12:52:36 | 599 s |
| 600 s | B2 / root | 12:52:36 | 597 s |

B1 encerrou por `network_below_threshold`. B2 encerrou por `host_below_threshold`.

Essas durações medem a permanência do episódio de alerta segundo o estado dos contadores. Não medem duração do ataque, tempo de contenção ou TTL de bloqueio.

### 7.1. Limite da unidade CAM

O limite operacional da unidade CAM permanece em:

`2025-12-12T12:47:56Z`.

Os três episódios da variante de 600 segundos encerraram depois desse limite, em razão da evolução temporal dos contadores no replay.

Esse resultado não amplia retrospectivamente a unidade de análise nem demonstra atividade atacante após o limite. Os encerramentos posteriores são registrados como comportamento do estado do motor.

## 8. Não disparos de B3 e criticidade

### 8.1. Decisões de B3

| Janela | `both_below_threshold` | `network_below_threshold` |
|---|---:|---:|
| 60 s | 164 | 54 |
| 300 s | 164 | 54 |
| 600 s | 166 | 54 |

Essas contagens representam snapshots de decisão. Não representam episódios independentes, ataques ou amostras adicionais.

A variante de 600 segundos apresentou dois snapshots adicionais com ambos os contadores abaixo do limiar. Portanto, a estabilidade das contagens de alertas não implica identidade completa da trajetória temporal entre variantes.

Na referência de 300 segundos, os máximos de rede associados por usuário foram 7 para `admin`, 3 para `root` e 5 para `john`, abaixo do limiar 10. `john` apresentou quatro falhas de host, abaixo do limiar 5.

A ausência de alerta B3 é um resultado observado sob o contrato adotado. Não foram reduzidos limiares para produzir um disparo.

### 8.2. Criticidade

Em cada janela, foram registradas 20 verificações com motivo:

`no_preexisting_active_alert`.

São verificações de B2 e B3, com dez ocorrências por modo. Não houve promoção crítica.

Sucesso de autenticação isolado não satisfaz a política de criticidade. A promoção requer alerta anterior ativo na chave correspondente e as demais condições do contrato.

B1 não utiliza mensagens de host para promoção crítica.

## 9. Rastreabilidade e verificações

As verificações concluídas confirmaram:

- Integridade dos arquivos declarados no manifesto.
- Preservação da configuração original.
- Variação exclusiva da janela nas configurações experimentais.
- Reprodução dos resultados pelo executor da Semana 8.
- Equivalência integral da variante de 300 segundos à referência da Semana 7.
- Existência dos IDs de evidência utilizados pelos alertas.
- Disponibilidade temporal das evidências no instante da abertura.

Na rastreabilidade, foram utilizados:

- `available` para evidências de autenticação.
- `end` para evidências de conexões curtas.

Nenhuma evidência de disparo verificada possuía disponibilidade posterior à abertura do alerta.

Os IDs dos alertas se repetem entre variantes. Para identificar um resultado desta campanha, deve-se utilizar a janela juntamente com o ID do alerta.

O pacote apresentou:

`semana8: sensibilidade conferida; metricas desabilitadas`.

A verificação final retornou status 0.

## 10. Métricas não estimadas

| Medida | Limitação nesta campanha |
|---|---|
| Falsos positivos e FP/host-dia | Classe benigna e exposição observável elegíveis não foram estabelecidas para esse cálculo. |
| Precisão, F1 e PR-AUC | Não há base de avaliação rotulada e protocolo suficiente para estimá-las validamente. |
| Recall | Não foi estabelecido um denominador validado de episódios positivos independentes para essa estimativa. |
| MTTD | Os instantes de abertura estão disponíveis, mas não foi estabelecida uma origem temporal de ataque adequada ao cálculo pretendido. |
| Eficácia de contenção no CAM | A campanha realiza replay offline; não executa bloqueio sobre o tráfego original. |
| Redução de FP de B3 em relação a B2 | Os recortes examinados não oferecem falhas SSH benignas elegíveis para essa comparação. |

Zero alertas no AIT não equivale a zero falsos positivos demonstrados.

A demonstração de nftables realizada na Semana 6 valida o mecanismo em laboratório controlado. Ela não acrescenta amostras à avaliação CAM/AIT nem demonstra contenção dos ataques originais.

## 11. Interpretação e limites

Nos dados selecionados, as janelas de 60, 300 e 600 segundos produziram as mesmas contagens de alertas, os mesmos usuários alertados e os mesmos instantes de abertura.

A sensibilidade observada manifestou-se nos encerramentos e nas durações dos episódios, além da diferença registrada nos snapshots de B3.

Esse resultado se limita aos recortes e parâmetros examinados. Não demonstra insensibilidade geral do motor à janela temporal.

A campanha reaplica três configurações aos mesmos dados. As nove ocorrências de alertas distribuídas entre variantes correspondem aos três episódios observados sob três parametrizações; não constituem nove ataques independentes.

Permanecem os seguintes limites:

- CAM restrito à variante puppet utilizada.
- AIT restrito aos recortes exploratórios de intranet-server e mail.
- Santos fora da ingestão e da campanha.
- Durações ausentes e associações desconhecidas preservadas como limitações.
- Duração curta até 5 segundos mantida como parâmetro operacional, sem demonstração de valor ótimo.
- Ausência de alerta B3 sem comprovação de vantagem em falsos positivos.
- Testes de software separados da evidência experimental.

A janela principal permanece em 300 segundos. A análise realizada não fundamenta sua substituição por uma janela considerada ótima.

## 12. Encaminhamento do CP5

A campanha fornece evidência técnica reproduzível para:

1. Comparação descritiva das saídas de B1, B2 e B3.
2. Análise delimitada da sensibilidade à janela temporal.
3. Rastreabilidade das evidências disponíveis no disparo.
4. Documentação dos não disparos e dos limites de interpretação.

Para o fechamento documental da Semana 8, devem ser concluídos:

- Texto de análise em `docs/analise-sensibilidade-semana8.md`.
- Atualização de `docs/gate-notas.md`.
- Conferência e versionamento dos documentos finais.

A continuidade prevista é integrar esses resultados à redação do capítulo de resultados e discussão, preservando a separação entre validação de software, observações CAM, exploração AIT e demonstração de mitigação em laboratório.

O CP5 registra a análise disponível e suas limitações. Não certifica eficácia generalizável nem substitui a revisão acadêmica.

## 13. Artefatos de referência

- `docs/protocolo-semana8.md`
- `scripts/semana8_sensibilidade.py`
- `tests/test_semana8.py`
- `docs/semana7-relatorio.md`
- `docs/resultados-semana7.md`
- `docs/cp3-relatorio.md`
- `docs/cp4-relatorio.md`
- `out/semana8/campanha-20261027T004827Z/manifest.json`
- `out/semana8/campanha-20261027T004827Z/qualidade.json`
- `out/semana8/campanha-20261027T004827Z/comparacao.csv`
- `out/semana8/campanha-20261027T004827Z/w060/result.json`
- `out/semana8/campanha-20261027T004827Z/w300/result.json`
- `out/semana8/campanha-20261027T004827Z/w600/result.json`

Os pacotes em `out/` permanecem fora do versionamento Git, conforme a política do projeto.