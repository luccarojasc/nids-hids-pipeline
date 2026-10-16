# CP1 — Gate de viabilidade do pipeline NIDS/HIDS

**Data:** 15/10/2026.  
**Decisão:** GO com ajuste de desenho; caminho (a) adotado após resultado negativo de (b).  
**Estado:** relatório para revisão, com pendências explícitas.

## 1. Objetivo e decisão

Verificar se os dados disponíveis sustentam a detecção de força bruta SSH e a comparação entre B1 (rede), B2 (host) e B3 (integrado), antes da implementação do motor.

A investigação adicional de `santos` foi concluída sem falhas SSH reconhecidas. A adoção de (a) foi registrada em `docs/gate-notas.md`: prosseguir com o CAM e os recortes elegíveis de `russellmitchell`, medindo FP onde houver rede e exposição adequadas. O item 5 permanece parcial. Os recortes examinados não oferecem falhas SSH benignas para testar redução de FP de B3 em relação a B2. `santos` permanece como resultado negativo documentado, fora da ingestão atual.

## 2. Proveniência

| Dados | Registro Zenodo / versão | Licença registrada no contexto |
|---|---|---|
| CAM: logs SSH `apt`, `healthcheck`, `puppet` | [18861762](https://zenodo.org/records/18861762) / v2 | CC-BY-4.0 |
| CAM: PCAPs de `puppet` | [18701095](https://zenodo.org/records/18701095) / v1 | CC-BY-4.0 |
| AIT: `russellmitchell` | [5789064](https://zenodo.org/records/5789064) / v2.0 | CC-BY-NC-SA-4.0 |
| AIT: `santos_no-pcaps.zip` | [19483937](https://zenodo.org/records/19483937) / v2.1 | Pendente de conferência específica |

MD5 dos logs CAM conferido em `docs/md5-camlds.txt`. Em `santos`, o MD5 `cb484a2c55ea03c63c556f0531fe8367` correspondeu à referência do guia; o teste interno do ZIP não encontrou erros. Extração: status 0, 6,8G e 12.165 arquivos. Raiz: `$TCC/data/raw/ait_ldsv2_1/santos_triagem`. `$AIT` permanece em `$TCC/data/raw/ait_ldsv2/russellmitchell`. Os ZIPs e resultados anteriores são preservados. Não se estende a verificação de integridade a pacotes sem evidência específica.

## 3. Evidências do gate

| Item | Veredito e evidência |
|---|---|
| 1 — falhas com IP/usuário | Aprovado. CAM agregado: 49 falhas do atacante `192.42.1.174` (`admin=21`, `root=15`, `john=13`). Em `puppet`: 16 (`7/5/4`, respectivamente). |
| 2 — sucesso após falhas | Aprovado como sequência. Seis sucessos de `john` no agregado; dois em `puppet`, às 12:42:37 e 12:42:55 de 12/12/2025. Não comprova disparo com o limiar padrão. |
| 3 — auditoria | Aprovado em `puppet`: 16 `USER_AUTH res=failed` corroboram as falhas do host; não somar novamente em `Nh`. |
| 4 — AttackMate | Parcial: inícios identificados; términos exatos dos passos não demonstrados. |
| 5 — atividade benigna AIT | Parcial: sucessos brutos presentes, nenhuma falha SSH nos dois testbeds examinados. |
| 5b — rede AIT | Parcial em `russellmitchell`: EVE/PCAPs encontrados; utilidade e cobertura host/janela pendentes. Rede de `santos` não validada. |
| 6 — formatos | Syslog e ISO 8601 reconhecidos nas amostras verificadas; revisão das categorias não classificadas não revelou falhas SSH omitidas. |
| 7 — PCAP CAM | Aprovado: `log.pcap.1765542807`, do firewall `inetfw`, contém 313 pacotes atacante→alvo:22 e 21 aberturas distintas com SYN observado. |

As aberturas CAM ocorreram entre **12:42:33.998535 e 12:42:54.804278 UTC**, em 12/12/2025, alinhadas ao ataque no host. Não equivalem a 21 conexões curtas ou autenticações atribuídas a `john`.

| Medida bruta AIT | `russellmitchell` | `santos` |
|---|---:|---:|
| Arquivos de autenticação lidos | 20 | 20 |
| Sucessos / falhas | 29 / 0 | 38 / 0 |
| Host-dias com falhas | 0 | 0 |
| Mediana de falhas nesses host-dias | Não aplicável | Não aplicável |

Ambos apresentaram zero `invalid_user`. Reconciliação das mensagens `sshd`: primeiro AIT, **130 = 29 + 101**; `santos`, **148 = 38 + 110**. As categorias restantes foram inspecionadas. Em `santos`, os 20 logs coincidem com o inventário, sem caminhos de `labels` ou `attacker_0`.

## 4. Validade e limites

- **Seleção benigna:** os totais AIT são brutos. Em `russellmitchell`, oito rótulos referenciam linhas 145–152 do `auth.log` de `intranet_server`; base 1 conferida por eventos distinguíveis. Não representam oito sucessos SSH a subtrair.

- **Período e relógio:** janela publicada do primeiro AIT: [21/01/2022, 25/01/2022); metadados locais de `santos`: [14/01/2022, 18/01/2022), sem fuso explícito. Recorte após normalização temporal. Ano/offset verificados somente em CAM `puppet` (2025/0) e AIT `intranet-server` (2022/0). `santos` continua sem validação de relógio e rótulos.

- **Regra e episódios:** `john` tem quatro falhas, abaixo de `θh=5`. Duração de conexão curta, fluxos incompletos e atribuição da rede ao par IP/usuário precisam ser definidos; SSH cifrado não revela diretamente o usuário ao sensor de rede. Fixar uma convenção de episódio sem apresentar o início do próximo passo como término comprovado.

- **Métricas:** motor ainda não executado; não há medição de FP. Comparação pareada exige cobertura equivalente, rótulos e deduplicação. FP/host-dia requer exposição observável, não dez hosts multiplicados por quatro dias. Diferenças de base, versão e instrumento limitam generalização; duas triagens não constituem oito réplicas.

## 5. Pendências e próximos passos

Antes de fechar o registro: informar horas ativas e espera pela transferência; verificar o teto de 2–3 h da triagem; confirmar data/status do pedido ao administrador; conferir DOI específicos e licença v2.1; completar contagens individuais de `apt`/`healthcheck`, sem deduzir sua distribuição do agregado.

Após revisão, seguir à seção **3.3** para versionar documentação, scripts e ambiente, excluindo dados e caches. O pesquisador encaminhará o CP1 ao orientador. Partes **4–5**: ingestão de host, depois rede; validar recortes, duração e correlação antes do motor. Sem Suricata/Apptainer, permanece a alternativa `tshark`. Zeek já foi retirado; demais cortes dependem das horas. A investigação não será ampliada automaticamente para outro testbed ou dados sintéticos.

**Evidências em `$TCC/docs/`:** `gate-notas.md`, `gate-camlds-auth.txt`, `gate-ait-auth.txt`, `gate-ait-santos-auth.txt`, `gate-camlds-puppet-syn.tsv`, relatórios de integridade/extração e `horas.md`. Detalhes conforme o prompt de continuidade e o guia vigente; a decisão e as saídas de 15/10/2026 atualizam o estado anterior.