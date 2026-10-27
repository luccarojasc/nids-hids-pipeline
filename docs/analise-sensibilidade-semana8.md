# Análise de sensibilidade à janela temporal — Semana 8

## 1. Objetivo e procedimento

A análise examinou como a janela temporal dos contadores influencia as saídas das configurações B1 (rede), B2 (host) e B3 (integrada). Foram utilizadas janelas de 60, 300 e 600 segundos sobre os mesmos eventos selecionados, mantendo 300 segundos como configuração principal.

A campanha foi executada em `out/semana8/campanha-20261027T004827Z`, com o código do commit `0a5011d57083f0fc6e1731465e28b748888520a7`.

Apenas a janela dos contadores foi alterada. Permaneceram fixos os limiares Nh ≥ 5 e Nn ≥ 10, a definição de conexão curta com duração positiva até 5 segundos, o horizonte de criticidade de 300 segundos e a idade máxima de associação de 300 segundos.

Também foram preservados os dados, as regras de seleção, os critérios de associação e a convenção de episódios. Não houve ajuste de limiares para obter disparos de B3.

A variante de 300 segundos reproduziu integralmente os resultados da referência da Semana 7. As outras variantes foram verificadas pelo executor específico da análise de sensibilidade.

## 2. Dados e alcance da comparação

A seleção compreendeu 57 eventos entre 219 registros de entrada: 26 eventos de autenticação e 31 de rede. Os 114 registros de auditoria permaneceram destinados à corroboração, sem incrementar novamente o contador de falhas.

Entre as mensagens de autenticação, 24 apresentaram candidato de rede único no instante da associação e duas não apresentaram candidato. Entre as conexões selecionadas, 23 tiveram usuário associado único e oito permaneceram sem usuário associado. Duas conexões apresentaram duração ausente.

Essas condições foram preservadas na análise. Ausência de associação não foi interpretada como evidência de atividade benigna, e duração ausente não foi convertida em duração zero.

A comparação considerou uma unidade CAM, correspondente à sequência SSH observada em puppet, e duas unidades exploratórias AIT, referentes a intranet-server e mail. As três janelas reutilizaram essas mesmas unidades; portanto, não acrescentaram amostras independentes.

## 3. Estabilidade das aberturas de alertas

As contagens de alertas permaneceram iguais nas três janelas.

| Unidade | B1 em cada janela | B2 em cada janela | B3 em cada janela |
|---|---:|---:|---:|
| CAM puppet | 1 | 2 | 0 |
| AIT intranet-server | 0 | 0 | 0 |
| AIT mail | 0 | 0 | 0 |

No CAM, B1 abriu um episódio associado à origem `192.42.1.174`. B2 abriu dois episódios, um para `admin` e outro para `root`. B3 não abriu episódios.

Os instantes de abertura também permaneceram iguais, conforme a tabela abaixo. Todos os horários são de 12/12/2025, em UTC.

| Configuração | Usuário | Abertura | Contador no disparo |
|---|---|---|---|
| B1 | Não aplicável | 12:42:36.403263 | Nn = 10 |
| B2 | admin | 12:42:37 | Nh = 7 |
| B2 | root | 12:42:39 | Nh = 5 |

Esse resultado é compatível com a concentração temporal das evidências de disparo, que puderam satisfazer os limiares mesmo na menor janela examinada.

A diferença entre um episódio B1 e dois episódios B2 deve ser interpretada considerando suas chaves de agregação. B1 não atribui usuário ao alerta, enquanto B2 distingue os usuários. A contagem bruta de episódios, isoladamente, não permite concluir qual configuração foi mais eficaz.

## 4. Sensibilidade dos encerramentos

Embora as aberturas tenham permanecido estáveis, os encerramentos se deslocaram com a janela temporal.

| Janela | Duração B1 | Duração B2 / admin | Duração B2 / root |
|---|---:|---:|---:|
| 60 s | 57.956585 s | 59 s | 57 s |
| 300 s | 297.956585 s | 299 s | 297 s |
| 600 s | 597.956585 s | 599 s | 597 s |

B1 encerrou por queda do contador de rede abaixo do limiar. B2 encerrou por queda do contador de host abaixo do limiar.

Na passagem de 60 para 300 segundos, os encerramentos foram deslocados em 240 segundos. Na passagem de 300 para 600 segundos, o deslocamento foi de 300 segundos. Como as aberturas permaneceram iguais, esses deslocamentos também aparecem nas durações dos episódios.

Portanto, a estabilidade das contagens não representa ausência de efeito da janela. Neste recorte, o efeito observado incidiu principalmente sobre o tempo de permanência do estado de alerta.

A duração de um episódio representa o intervalo entre sua abertura e seu encerramento segundo o contrato do motor. Ela não corresponde à duração comprovada do ataque, ao tempo de contenção ou ao TTL de bloqueio.

## 5. Encerramentos posteriores ao limite operacional CAM

A unidade CAM possui limite operacional em `2025-12-12T12:47:56Z`.

Nas janelas de 60 e 300 segundos, os três episódios encerraram antes desse limite. Na janela de 600 segundos, B1 encerrou às 12:52:34.359848 UTC e os dois episódios B2 encerraram às 12:52:36 UTC.

Esses encerramentos posteriores decorrem da evolução temporal dos contadores no replay. Não demonstram atividade atacante após o limite da unidade e não justificam sua ampliação retrospectiva.

A análise mantém separados o intervalo operacional utilizado para descrever a unidade e a duração do estado de alerta calculada pelo motor.

## 6. Ausência de disparos de B3

B3 não abriu alertas em nenhuma das três janelas.

Na referência de 300 segundos, os máximos de conexões curtas associadas por usuário foram 7 para `admin`, 3 para `root` e 5 para `john`, abaixo do limiar de rede igual a 10. Para `john`, o máximo de falhas de host foi 4, também abaixo do limiar de host igual a 5.

Os motivos registrados nos snapshots de decisão foram:

| Janela | Ambos os contadores abaixo do limiar | Contador de rede abaixo do limiar |
|---|---:|---:|
| 60 s | 164 | 54 |
| 300 s | 164 | 54 |
| 600 s | 166 | 54 |

Esses registros são estados observados durante o replay, não episódios independentes. A variante de 600 segundos apresentou dois snapshots adicionais com ambos os contadores abaixo do limiar, apesar de manter a mesma contagem final de alertas.

A ausência de disparo de B3 evidencia uma limitação observada da configuração integrada para produzir alertas nesse recorte com os parâmetros adotados. Não constitui evidência de redução de falsos positivos, pois o contraste necessário com falhas SSH benignas elegíveis não está disponível.

O resultado deve ser apresentado juntamente com os disparos de B1 e B2, preservando os parâmetros definidos previamente.

## 7. Criticidade

Nenhum episódio foi promovido a crítico.

Em cada janela, foram registradas 20 verificações com o motivo `no_preexisting_active_alert`: dez em B2 e dez em B3.

Os sucessos de autenticação, por si só, não satisfazem a política de criticidade. A promoção exige alerta anterior ativo na chave correspondente e o atendimento das demais condições do contrato. B1 não utiliza mensagens de host para promoção crítica.

No CAM, os alertas B2 foram associados a `admin` e `root`, enquanto os sucessos observados do atacante envolveram `john`. Este usuário permaneceu abaixo do limiar de falhas. A existência de sucessos para a mesma origem não permite transferir automaticamente a criticidade entre usuários.

## 8. Interpretação dos recortes AIT

Os recortes AIT de intranet-server e mail permaneceram sem alertas em B1, B2 e B3 nas três janelas.

Esse resultado descreve a saída do motor sobre os eventos selecionados. Não permite afirmar que houve zero falsos positivos, pois esses recortes não possuem classe benigna confirmada e exposição elegível estabelecida para essa estimativa.

A presença de sucessos de autenticação e de conexões curtas também não basta para classificar automaticamente toda a atividade como benigna ou maliciosa.

O AIT permanece como material exploratório para examinar ingestão, associação e comportamento do motor. O item 5 do gate continua parcial, e Santos permanece fora da ingestão.

## 9. Rastreabilidade e reprodutibilidade

As verificações confirmaram que os IDs das evidências utilizadas nos disparos existem e que suas disponibilidades temporais não são posteriores às aberturas dos alertas.

Para autenticação, foi utilizado o instante `available`. Para conexões curtas, foi utilizado `end`, preservando a necessidade de observar o encerramento antes de utilizar a duração como evidência.

A campanha verificou hashes, reprodução dos resultados, variação exclusiva da janela e equivalência integral da variante de 300 segundos à referência da Semana 7.

Os IDs de alerta se repetem entre variantes. Sua identificação no contexto da campanha deve combinar janela e ID.

A validação do executor incluiu oito testes específicos da Semana 8. A suíte completa apresentou 98 testes aprovados. Esses testes sustentam a verificação do software, sem ampliar a amostra experimental.

## 10. Limites das conclusões

A análise permite afirmar que, nos recortes examinados, as janelas de 60, 300 e 600 segundos preservaram as contagens, os usuários alertados e os instantes de abertura, mas alteraram os encerramentos e as durações dos episódios.

Não permite concluir que o motor seja insensível à janela em outros cenários ou que alguma dessas janelas seja ótima.

Também não foram estimados precisão, recall, F1, PR-AUC, FP/host-dia ou MTTD. Os instantes de abertura disponíveis não resolvem, por si só, as limitações de rótulos, exposição, denominadores e origem temporal necessárias a essas medidas.

A reaplicação de três janelas aos mesmos dados não representa três experimentos independentes. Os três episódios observados sob cada parametrização não devem ser somados como nove ataques distintos.

A demonstração de mitigação da Semana 6 permanece uma evidência separada de funcionamento do mecanismo em laboratório. Ela não demonstra contenção do tráfego original CAM/AIT.

## 11. Implicações para a continuidade

A janela de 300 segundos permanece como configuração principal. As variantes de 60 e 600 segundos integram a análise de sensibilidade, sem substituir retrospectivamente a configuração de referência.

Na redação dos resultados e da discussão, deverão ser apresentados:

- As aberturas observadas em B1 e B2 e os não disparos de B3.
- A estabilidade das aberturas diante das três janelas.
- A variação dos encerramentos e das durações dos episódios.
- Os limites operacionais da unidade CAM.
- O caráter exploratório dos resultados AIT.
- A separação entre validação técnica e avaliação de eficácia.

Os detalhes de proveniência, hashes, verificações e métricas não estimadas estão registrados em `docs/cp5-relatorio.md`.