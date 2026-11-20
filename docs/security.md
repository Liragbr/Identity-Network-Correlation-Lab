# Escopo, segurança e confidencialidade

## Isolamento

- Servidores HTTP/TCP/UDP escutam apenas em `127.0.0.1`.
- Os clientes usam apenas aliases `127.0.0.2`, `.3`, `.4` (rede de loopback Linux).
- Não existe argumento de linha de comando para inserir alvo remoto, rede ou senha de terceiros.
- Nenhuma dependência de rede externa é executada pelo cenário.
- O gateway HTTP é propositalmente um **mock local**, sem certificados nem proteção de produção: nunca expor ou implantar como serviço corporativo.

## Dados

- Contas, senhas de teste, serviços e indicadores são exclusivos do laboratório.
- O cliente envia credenciais de teste ao gateway local; os logs **não registram senhas**.
- O repositório não contém documentos, capturas ou consultas internas de empregadores/clientes.
- `examples/` apresenta saída exclusivamente de uma execução local controlada do código fornecido.

## Publicação

Não adicionar capturas reais de NDR/EDR, exports ITSM, nomes de clientes, IPs internos de clientes, usernames, chaves, domínios corporativos ou trechos de relatórios confidenciais. Para futuras contribuições, utilize exclusivamente dados produzidos por este lab ou dados públicos cuja licença autorize redistribuição.

## Responsabilidade técnica

Recomendar investigação e contexto, não contenção automática, para heurísticas que podem gerar falsos positivos. O código não tenta executar senhas em diretórios externos, não varre redes reais e não coleta informações de sistemas de terceiros.
