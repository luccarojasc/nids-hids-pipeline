# Contrato operacional do núcleo — Semana 4

Versão: semana4_v1. Configuração: config/motor-semana4.json.

O núcleo offline recebe uma lista fechada de seis Parquets da ingestão CAM puppet e AIT russellmitchell. Valida fontes, esquema, contagens, duração e identidades antes de processar. Auditd permanece corroboração e não incrementa Nh. Mensagens ssh_invalid_user também não entram nesse contador.

A janela é (t−300 s, t]. Os limiares 5 para host e 10 para rede ficam registrados para a etapa de alertas. Conexões curtas são TCP destinado à porta 22, com SYN observado e duração positiva de até 5 s, até o primeiro FIN/RST. Duração ausente não é zero. A escolha dos 5 s ocorreu após inspeção e permanece exploratória.

Nh conta falhas system.auth/ssh_login por base, cenário, destino/host, origem e usuário. Nn_rede conta conexões por origem e destino/serviço, sem depender de mensagens de host. Nn_associado é o subconjunto atribuível a um único usuário na evidência disponível naquele instante. As contagens são observações técnicas, não alertas.

A ordem lógica disponibiliza uma mensagem de host ao fim do segundo que contém seu timestamp. A rede disponibiliza abertura no SYN e fechamento apenas no primeiro FIN/RST. O SYN precisa estar na janela quando a conexão contribui para Nn. Eventos no limite esquerdo expiram, inclusive sem novos pacotes. O código emite snapshots após processar todo o lote de um mesmo instante.

A associação exige mesmo cenário, alvo/serviço, IP e porta de origem. O SYN deve estar entre timestamp_host−300 s e o fim exclusivo do segundo do host. Se o fechamento já for conhecido, admite-se timestamp_host até 1 s após ele. Essas tolerâncias são convenções operacionais desta versão, não valores universais do SSH nem correção de fuso.

Sem porta/candidato, a associação é desconhecida. Mais de uma conexão candidata ou mais de um usuário tornam a conexão ambígua para o contador por usuário. Uma associação inicialmente única pode ser invalidada depois; o estado corrente muda, e o histórico não é reescrito. Não replicar conexões entre usuários. Sucesso pode fornecer evidência de usuário, mas não incrementa Nh nem implementa criticidade nesta etapa.

A identidade de host usa caminho original e linha física; a da rede usa caminho do PCAP e stream, sempre com base/cenário. Repetições idênticas da mesma identidade são deduplicadas. Conflitos, possíveis cópias entre arquivos ou sobreposições conhecidas interrompem a execução para revisão. Não há remontagem entre PCAPs; reutilização de porta com conexão anterior incompleta pode ficar ambígua.

CAM usa puppet/172.17.100.122:22 e sensor inetfw. AIT usa intranet-server/10.143.2.4:22 e mail/172.19.130.4:22, com sensores correspondentes. O período AIT é operacionalmente [21/01/2022,25/01/2022), UTC; a ausência de fuso nos metadados permanece ressalva. Não há aquecimento anterior ao recorte; suas fronteiras podem censurar evidências.

As saídas incluem eventos, exclusões, tentativas de associação, snapshots e manifesto de hashes. O relógio lógico não mede atraso real de ingestão ou tempo real de resposta. Ausência de eventos não comprova cobertura contínua. AIT permanece técnico/exploratório, sem FP/host-dia ou redução de FP. O núcleo não gera alertas, score, criticidade ou mitigação; esses componentes pertencem às próximas etapas.