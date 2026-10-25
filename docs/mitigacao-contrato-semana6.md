# Contrato de mitigação — Semana 6

Versão: `semana6_v1`.
Data de consolidação: 25/10/2026, America/Sao_Paulo.
Escopo: política offline e demonstração controlada do mecanismo de contenção.

## 1. Interface e relógio

A referência é `out/semana5/execucao-20261021T020309Z`.

A camada de mitigação recebe transições `open`, `critical` e `close`, preservando os identificadores dos alertas. Score e TTL são obtidos da transição no instante da decisão, sem aplicação retrospectiva do estado final do alerta.

A execução offline utiliza nanossegundos lógicos. A demonstração em VM utiliza tempo monotônico real e registra o perfil e o divisor temporal.

Os parâmetros do detector da Semana 5 permanecem preservados. B1, B2 e B3 mantêm estados separados. Não há integração em tempo real com sensores.

## 2. Chave de contenção

A chave contém:

- Modo: B1, B2 ou B3.
- Dataset e cenário.
- Host e endereço IPv4 de destino.
- Serviço TCP/22.
- Endereço IPv4 de origem.

O usuário permanece na proveniência do alerta, mas não integra a chave de firewall. Alertas de usuários distintos podem compartilhar uma contenção quando os demais componentes da chave coincidem.

## 3. Política de TTL

- Solicitação normal: 900 segundos após a solicitação.
- Promoção crítica: 1.800 segundos após a promoção.
- Renovação: máximo entre o prazo existente e o instante da solicitação acrescido do TTL.
- Pedido que não amplia o prazo: `retain`, sem atualização do firewall.
- Duplicata idêntica: ignorada, sem nova renovação.
- Mesmo identificador com conteúdo divergente: erro.
- Encerramento do alerta (`close`): não remove a contenção antes do prazo.
- Expiração: processada na fronteira do prazo, antes de uma solicitação no mesmo instante.

A reprodução offline drena os temporizadores restantes. Expirações posteriores ao período dos dados representam projeções da política.

A idempotência é garantida dentro da execução. Não há persistência de estado para recuperação automática de um serviço, daemon ou coordenação distribuída.

## 4. Execução offline

A execução preservada está em:

`out/semana6/execucao-20261021T111452Z`

O executor é `simulation_only`. As ações `apply`, `renew` e `expire` desse pacote não representam comandos executados no firewall.

O pacote contém configuração, alertas, transições, solicitações derivadas, ações, resumo e manifesto. O marcador `SUCCESS` é produzido após a verificação das saídas.

A simulação não remove eventos posteriores dos dados e não demonstra interrupção do ataque observado.

## 5. Demonstração em VM

O adaptador real é restrito ao namespace descartável do servidor em VM própria.

O ambiente utiliza:

- Origem: `192.0.2.2`.
- Destino: `192.0.2.1`.
- Porta sujeita à contenção: TCP/22.
- Porta de controle: TCP/2222.

O servidor é um serviço TCP mínimo, sem autenticação SSH. Nenhum endereço CAM/AIT é aplicado à rede da organização.

A renovação remove e reinsere o elemento temporizado em um único lote `nft -f`. A expiração efetiva é verificada pelo retorno da conectividade após o prazo renovado. A limpeza remove somente os recursos criados pela demonstração.

A execução realizada utilizou o perfil `accelerated`, com divisor 150 e TTLs reais de 6 e 12 segundos. Esse perfil demonstra o mecanismo, sem comprovar permanência física de 900 ou 1.800 segundos. O perfil integral `contract` não foi executado nesta etapa.

A cópia das evidências está em:

`out/semana6/evidencias-vm/out/demo-20261025T162436Z`

O relatório CP4 registra ambiente, resultados, proveniência e hashes dos pacotes offline e da VM separadamente.

## 6. Limites

Não foram medidas taxas de bloqueios corretos ou indevidos, interrupção do ataque CAM, interrupção de sessões SSH preexistentes ou desempenho em produção.

O AIT permanece exploratório, com métricas desabilitadas. O resultado B3 sem alerta nos dados de referência é preservado.

Os casos controlados de criticidade, renovação e duplicação verificam o mecanismo e não ampliam a amostra experimental.

Nenhuma ação de firewall foi executada na Workstation2. A demonstração real ficou restrita à VM própria.