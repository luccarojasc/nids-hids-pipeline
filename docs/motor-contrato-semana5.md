# Contrato do motor — Semana 5

Versão: semana5_v1. Continuidade de semana4_v1. Escopo: decisões offline B1/B2/B3 e fechamento técnico do CP3.

## Entradas e preservação

A referência é out/semana4/execucao-20261018T163915Z: 219 registros brutos e 57 eventos selecionados, 26 auth e 31 rede. Os seis Parquets, a configuração e os quatro módulos originais da Semana 4 são preservados e conferidos por hash. Auditd permanece corroboração. As entradas ativas de rede são as extrações TShark CAM/AIT; os EVE históricos não são somados.

## Decisões

Janela (t−300 s,t], Nh≥5, Nn≥10, conexão curta com 0<d≤5 s, método syn_to_first_fin_or_rst_v1. Duração ausente não equivale a zero. Evidência de rede só contribui depois do primeiro FIN/RST conhecido; auth torna-se disponível ao final do segundo representado. Associação mantém os critérios da Semana 4.

| Modo | Critério | Dependência |
|---|---|---|
| B1 | Nn_rede≥10 | Somente rede; sem usuário e sem criticidade por host |
| B2 | Nh≥5 por usuário | Somente auth |
| B3 | Nh≥5 e Nn_associado≥10 por usuário no mesmo instante | Rede e auth, associação única |

Nenhuma conexão desconhecida ou ambígua é atribuída arbitrariamente a todos os usuários. Sucessos podem associar uma conexão, mas não aumentam Nh.

## Score e criticidade

Score diagnóstico: S_h=min(50,floor(50×Nh/5)); S_n=min(50,floor(50×Nn/10)). B1 usa S_n; B2 usa S_h; B3 usa min(S_h,S_n). Condições explícitas, não soma de scores, decidem o disparo. Alerta normal: 50. Crítico: 100. Trata-se de escala ordinal de engenharia, não probabilidade calibrada.

Em B2/B3, criticidade requer alerta já ativo antes do lote atual, condição-base ainda satisfeita, sucesso do mesmo dataset/cenário/alvo/serviço/IP/usuário, timestamp bruto estritamente posterior à abertura e disponibilidade até 300 s após a abertura. Empates e sucesso no lote de abertura são rejeitados conservadoramente. B3 exige também associação única do sucesso após processar todas as associações do lote; sua conexão não precisa ser curta. Há no máximo uma promoção por episódio.

TTL recomendado: 900 s normal e 1.800 s crítico. Não há execução de bloqueio, renovação ou expiração nesta versão.

## Episódios e comparação

Um episódio técnico abre na transição falsa→verdadeira; novas aberturas da chave são suprimidas enquanto verdadeiro. A transição para falso encerra e rearma. Fim do replay sem encerramento deixa o fim ausente, explicitamente censurado. Alteração posterior da associação não apaga o histórico já produzido. Episódio técnico não é rótulo de ataque ou intervalo de bloqueio.

A unidade descritiva comum contém dataset, cenário, alvo/serviço, origem e intervalo. Compara ocorrência de abertura por modo, mantendo contagem e IDs como detalhes. B1 não é replicado por usuário. O intervalo CAM [2025-12-12T12:42:33.203732Z,2025-12-12T12:47:56Z) é convenção operacional posterior à inspeção: início do passo hydra interpretado em UTC e fim derivado da disponibilidade do último sucesso mais 300 s. Não é término comprovado do ataque. AIT usa [2022-01-21,2022-01-25) UTC para intranet-server e mail, sem benignidade certificada. As unidades não filtram o replay e não são réplicas independentes.

## Sigma e rastreabilidade

Três regras-base: falha SSH, sucesso SSH e conexão curta. O adaptador local suporta somente o subconjunto declarado em rules.py; agregação e estado ficam em Python. Não se declara backend Sigma geral. Seleções são reconciliadas com o contrato do núcleo.

Pacote de execução: configurações, eventos, correspondências de regras, decisões, alertas, transições, avaliações de criticidade, trilha de contadores, comparação, resumo, cópias das regras e manifesto com hashes. SUCCESS indica as verificações implementadas concluídas, não certificação de rótulos ou eficácia.

## Limites

AIT é exploratório, sem métricas FP/host-dia. Item 5 do CP1 permanece parcial; Santos continua fora. Não se promete superioridade B3 nem se reduzem limiares para obter disparo. Positivos controlados nos testes validam o software e não ampliam a amostra experimental. Escopo e resultados efetivos constam de cp3-relatorio.md.