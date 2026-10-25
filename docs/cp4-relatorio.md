# CP4 — Política de TTL e mecanismo de contenção

Data da conferência: 25/10/2026, America/Sao_Paulo.

Estado: política offline, demonstração acelerada e revisão das capturas nftables concluídas tecnicamente no escopo delimitado. Consolidação da documentação e versionamento final em andamento.

## 1. Objetivo e implementação

Implementar a interface entre transições de alertas e solicitações de contenção, com TTL normal de 900 segundos, TTL crítico de 1.800 segundos, renovação sem redução de prazo, deduplicação e expiração.

A implementação está em `src/mitigation/`, `config/mitigacao-semana6.json` e `scripts/semana6_vm_demo.py`. O contrato está em `docs/mitigacao-contrato-semana6.md`.

O detector e os parâmetros da Semana 5 foram preservados. Não foram reduzidos limiares para produzir alertas ou ações B3.

A chave de contenção agrega usuários da mesma origem, alvo e serviço, mantendo modos, datasets e cenários separados. O usuário permanece na proveniência do alerta.

## 2. Testes automatizados

| Verificação | Resultado | Tempo | Status |
|---|---:|---:|---:|
| Testes da Semana 6 | 33 aprovados | 0,41 s | 0 |
| Suíte completa | 90 aprovados | 0,52 s | 0 |

As verificações abrangem TTL, renovação, retenção do maior prazo, duplicatas e conflitos, fronteiras temporais, isolamento de escopos, não retroação de criticidade, falhas do executor e limpeza simulada.

Testes com executor substituto não comprovam, isoladamente, funcionamento do nftables no kernel. A demonstração em VM constitui evidência adicional e separada.

## 3. Execução offline

### 3.1 Referência e proveniência

- Referência: `out/semana5/execucao-20261021T020309Z`.
- Execução: `out/semana6/execucao-20261021T111452Z`.
- Python: `3.10.12`.
- `git_head` registrado: `401dab6dacfc96b47275b2f009cecc12a5c65a2b`.
- Executor: `simulation_only`.
- Métricas: desabilitadas.

SHA-256 da configuração de entrada:

`fac9b5a95df8f67f82302473503da0cfd8e5a6d17d8f6980d76a46036194f3ba`

SHA-256 do manifesto de referência da Semana 5:

`47b31bbe596cf06d8d24df106d3f6c08aa9262ed04bbf5ef1ac4e83bc9455010`

Os hashes individuais das fontes e saídas estão preservados em `manifest.json` da execução. O `git_head` identifica o estado Git registrado naquele instante; os hashes das fontes identificam o conteúdo efetivamente utilizado.

Os comandos `inspect`, `run` e `verify` terminaram com status 0. O marcador `SUCCESS` contém:

> semana6: politica offline conferida; firewall nao executado

### 3.2 Resultados observados

| Modo | apply | renew | retain | expire | close_ignored | duplicate_ignored |
|---|---:|---:|---:|---:|---:|---:|
| B1 | 1 | 0 | 0 | 1 | 1 | 0 |
| B2 | 1 | 1 | 0 | 1 | 2 | 0 |
| B3 | 0 | 0 | 0 | 0 | 0 | 0 |

Foram processadas seis solicitações únicas: três aberturas e três encerramentos. Os temporizadores foram drenados e não restaram contenções ativas ao final.

Instantes abaixo em UTC, em 12/12/2025:

| Modo e ação | Instante lógico | Prazo resultante |
|---|---|---|
| B1 — aplicação | 12:42:36.403263 | 12:57:36.403263 |
| B2 — aplicação por admin | 12:42:37 | 12:57:37 |
| B2 — renovação por root | 12:42:39 | 12:57:39 |
| B1 — encerramento ignorado | 12:47:34.359848 | Mantido |
| B2 — dois encerramentos ignorados | 12:47:36 | Mantido |
| B1 — expiração projetada | 12:57:36.403263 | Sem contenção ativa |
| B2 — expiração projetada | 12:57:39 | Sem contenção ativa |

Os alertas de admin e root compartilham a chave de contenção B2. O segundo amplia o prazo em dois segundos.

Todas essas ações são simuladas. Elas não alteram os eventos do dataset nem demonstram interrupção do ataque CAM. As expirações após os eventos são projeções da política.

## 4. Demonstração em VM

### 4.1 Ambiente e escopo

- Hostname: `tcc-lab`.
- Virtualização identificada: `oracle`, correspondente ao VirtualBox utilizado.
- Sistema convidado: Ubuntu.
- Kernel: `6.8.0-147-generic`.
- Python: `3.12.3`.
- Perfil: `accelerated`.
- Divisor temporal: 150.
- TTLs reais utilizados: 6 e 12 segundos.
- Perfil integral de 900/1.800 segundos: não executado.

As versões específicas de nftables, iproute2 e VirtualBox não constam do registro de ambiente apresentado nesta conferência; não foram inferidas.

A execução utilizou os namespaces `tcc6_cli_1ea9ea43` e `tcc6_srv_1ea9ea43`, origem `192.0.2.2` e destino `192.0.2.1`.

TCP/22 foi a porta sujeita à contenção; TCP/2222 foi o controle. O servidor era um serviço TCP mínimo, sem autenticação SSH.

Antes da execução, a interface externa da VM estava sem portadora e a pasta compartilhada havia sido desmontada. A transferência das evidências ocorreu após a demonstração e a limpeza.

### 4.2 Política controlada

O ensaio foi identificado como `controlled_test`, cenário `ttl_demo`, no modo B2. Ele não corresponde a novos alertas CAM/AIT.

Foram observadas:

- Uma aplicação.
- Uma renovação.
- Uma retenção de prazo.
- Uma expiração.
- Dois encerramentos ignorados.
- Uma duplicata ignorada.
- Cinco solicitações únicas.
- Nenhuma contenção ativa ao final.

A duplicata de `critical-a` não gerou nova renovação. A solicitação posterior com TTL menor não reduziu o prazo existente.

O campo `simulation_only` dentro de `policy_summary` descreve o cálculo da política controlada. As ações pertinentes foram executadas no nftables pelo adaptador de laboratório, com efeito avaliado pelas sondas de conectividade.

### 4.3 Sondas e limpeza

Os tempos abaixo são os valores de `elapsed_ns`, convertidos para segundos e arredondados a três casas. Representam o instante de registro relativo ao início do script, não latência de detecção ou instante exato de expiração.

| Sonda | Porta | Retorno esperado | Retorno observado | Tempo relativo (s) |
|---|---:|---:|---:|---:|
| before_allowed | 22 | 0 | 0 | 1,032 |
| control_before_allowed | 2222 | 0 | 0 | 1,066 |
| apply_blocked | 22 | 2 | 2 | 1,747 |
| apply_control_allowed | 2222 | 0 | 0 | 1,781 |
| renew_blocked | 22 | 2 | 2 | 3,776 |
| renew_control_allowed | 2222 | 0 | 0 | 3,813 |
| after_original_deadline_still_blocked | 22 | 2 | 2 | 8,217 |
| after_expiry_allowed | 22 | 0 | 0 | 15,636 |
| after_expiry_control_allowed | 2222 | 0 | 0 | 15,688 |

Na sonda utilizada, retorno 0 significa conexão estabelecida e retorno 2 significa timeout. Todas as nove sondas corresponderam ao resultado esperado, com `stderr` vazio.

A porta 22 estava acessível antes da aplicação, ficou bloqueada após aplicação e renovação, continuou bloqueada após o prazo original e voltou a aceitar conexão após o prazo renovado. A porta 2222 permaneceu acessível nas verificações de controle.

A limpeza foi registrada em aproximadamente 15,735 segundos. A remoção dos dois namespaces retornou 0, com `stderr` vazio. Uma consulta posterior com `ip netns list` não listou namespaces.

O manifesto registra `completed: true`. O marcador `SUCCESS` contém:

> semana6: mecanismo nftables demonstrado em VM isolada

As quatro capturas nftables foram inspecionadas. A regra de descarte utiliza o conjunto `ssh_block` para a origem, destino `192.0.2.1` e porta TCP/22.

| Captura | Elemento de origem | timeout | expires | Pacotes | Bytes |
|---|---|---:|---:|---:|---:|
| after-apply.json | 192.0.2.2 | 6 s | 5 s | 0 | 0 |
| after-renew.json | 192.0.2.2 | 12 s | 11 s | 1 | 60 |
| after-original-deadline.json | 192.0.2.2 | 12 s | 6 s | 3 | 180 |
| after-expiry.json | Ausente | — | — | 3 | 180 |

O contador inicial zerado corresponde à ordem do script: a captura após aplicação precede a primeira sonda bloqueada. Os contadores são acumulados da regra e não representam autenticações SSH.

O campo `expires` registra o prazo restante exibido no momento da captura, sem estabelecer o instante exato da expiração. Após o prazo original, o elemento renovado ainda estava presente e a sonda permanecia bloqueada. Após o prazo renovado, o conjunto não apresentava elementos, a porta 22 voltou a aceitar conexão e o contador permaneceu em três pacotes e 180 bytes.

A regra permaneceu instalada nessa última captura, mas sem elemento no conjunto que correspondesse à origem testada. A limpeza posterior removeu os namespaces. A leitura das quatro capturas terminou com status 0.

### 4.4 Preservação e integridade da transferência

Pasta original na VM:

`/home/tcc/tcc-semana6-lab/out/demo-20261025T162436Z`

Pacote preservado na Workstation2:

`out/semana6/evidencias-semana6-vm.tar.gz`

Cópia extraída na Workstation2:

`out/semana6/evidencias-vm/out/demo-20261025T162436Z`

SHA-256 do pacote, coincidente na VM, no Windows e na Workstation2:

`9528ccafd1cfc6b6665071e0ff972df4f6650a6d430fefd74791f705fe16acd8`

SHA-256 do manifesto da demonstração:

`d0b2e4c97cf612e96d4e30b6a488c3c7075a352ec740bafb4644151327da60a5`

A listagem do pacote e a extração terminaram com status 0. Os hashes individuais das fontes e dos arquivos de evidência constam do manifesto preservado.

## 5. Limites e conclusão

A política offline, os testes automatizados e o efeito observado no laboratório constituem evidências distintas.

A demonstração acelerada sustenta o funcionamento observado de aplicação, renovação e expiração da contenção TCP no ambiente testado. Não comprova permanência física de 15/30 minutos, autenticação SSH, interrupção de sessões preexistentes, recuperação sob carga ou mitigação do ataque CAM.

Os tempos registrados são observações locais da VM, não MTTD nem latência de contenção do dataset.

Nenhuma ação de firewall foi executada na Workstation2. O AIT permanece exploratório, com métricas desabilitadas. Não foram calculadas taxas de falsos positivos, bloqueios indevidos ou eficácia comparativa da contenção.

O resultado B3 sem alertas foi preservado. Casos controlados não ampliam a amostra experimental.

As verificações offline, as sondas comportamentais, a revisão das capturas nftables, a limpeza do laboratório e a consolidação da documentação foram concluídas. Permanecem a conferência do versionamento e o envio ao repositório remoto. Este relatório não implica aprovação do orientador.